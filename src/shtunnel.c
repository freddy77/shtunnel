/* shtunnel - program to tunnel tcp stream in a shell session
 * Copyright (C) 2004  Frediano Ziglio
 * -----
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include "includes.h"
#include <assert.h>
#include "sshpty.h"

typedef unsigned char uchar;

static const uchar magic = 0xF0;
#define MAGIC_PREFIX_LEN 6
static const char magicInit[] = "ShellTunnelInit";

typedef enum {
	Free,
	Connected,	/* represent a tcp/ip channel */
	Listen,		/* represent a socket listening */
	RemoteListen	/* remote listening channel */
} ChannelType;

typedef enum {
	CmdListen = 49,
	CmdConnect,
	CmdAccept,
	CmdClose,
	CmdShutdown,
	CmdWindowChanged,
	CmdBlockData
} CommandType;

typedef struct buffer {
	uchar *ptr;
	unsigned int len;
	unsigned int size;
} buffer;

typedef struct channel {
	ChannelType type;
	int number;
	int fd;		/* file descriptor */
	int accepted;	/* file descriptor of accepted socket */
	int local;	/* local port */
	int remote;	/* remote port */
	buffer buf;	/* buffer to hold data */
	unsigned int blocked:1;	/* block read from socket to avoid dead lock */
	unsigned int remote_blocked:1;	/* remote channel blocked */
	unsigned int connected:1;
	in_addr_t ip;	/* address for local listen */
} channel;

static channel channels[256];
#define FOREACH_CHANNEL_BEGIN {channel *ch; for (ch = channels; ch != channels + (sizeof(channels)/sizeof(channels[0])); ++ch) {
#define FOREACH_CHANNEL_END   }}

static int client = 1;
static const char *shellCmd = NULL;
static int initialized = 0;
static int debugEnabled = 0;
static const char * logFile = "log.txt";
static char endPoint[32] = ""; /* "client" or "server" */

static int WRITE = -1;
static const int STDOUT = 1;
static const int STDERR = 2;

#define MAX_CONTROL_LEN 260
#define MAX_DATA_LEN 1000
/* buffer till this size */
#define BLOCK_DATA_LIMIT 2048
/* unblock when buffer size it's down this limit */
#define UNBLOCK_DATA_LIMIT 1024

static uchar control[MAX_CONTROL_LEN];
static int control_len = 0;

/* program should terminate on signal */
static volatile int must_quit;
/* program have received a windows change */
static volatile int window_changed;
static volatile int child_exited;

static void sendCommand(int fd, CommandType type, int channel, int port);
static void check_window_change(void);
static void write_channel_data(channel *ch, uchar *data, unsigned int len);

/*
 * Logging functions
 */

void fatal(const char *msg, ...)
{
	va_list ap;

	if (!client)
		sendCommand(STDOUT, CmdShutdown, 0, 0);
	leave_raw_mode();

	fprintf(stderr, "fatal error: ");

	va_start(ap, msg);
	vfprintf (stderr, msg, ap);
	va_end(ap);

	fprintf(stderr, "\n");
	exit(1);
}

void error(const char *msg, ...)
{
	va_list ap;

	fprintf(stderr, "error: ");

	va_start(ap, msg);
	vfprintf (stderr, msg, ap);
	va_end(ap);

	fprintf(stderr, "\n");
}

void debug(const char *msg, ...)
{
	va_list ap;
	static FILE *log = NULL;

	if (!debugEnabled)
		return;

	if (!log) {
		log = fopen(logFile, "a");
		if (!log)
			fatal ("Error opening log file");
	}
	va_start(ap, msg);
	vfprintf(log,  msg, ap);
	va_end(ap);
	fprintf(log, "\n");
	fflush(log);
}

static void debug_dump(const char *msg, const void *buf, int length)
{
	int i;
	int j;
	const int bytesPerLine = 16;
	char line[16 * 4 + 40], *p;
	const unsigned char *data = (const unsigned char *) buf;

	if (!debugEnabled)
		return;

	if (msg)
		debug("%s", msg);

	for (i = 0; i < length; i += bytesPerLine) {
		p = line;
		/* print the offset as a 4 digit hex number */
		sprintf(p, "%04x", i & 0xffff);
		p += 4;

		/* print each byte in hex */
		for (j = 0; j < bytesPerLine; ++j) {
			if (j + i >= length)
				sprintf(p, "   ");
			else
				sprintf(p, "%c%02x", j == bytesPerLine / 2 ? '-' : ' ', data[i + j]);
			p += 3;
		}

		/* skip over to the ascii dump column */
		sprintf(p, " |");
		p += 2;

		/* print each byte in ascii */
		for (j = i; j < length && (j - i) < bytesPerLine; ++j) {
			if (j - i == bytesPerLine / 2)
				*p++ = ' ';
			*p++ = isprint(data[j]) ? data[j] : '.';
		}
		strcpy(p, "|");
		debug("%s", line);
	}
}
/*
 * Buffer functions
 */
/*
static void buffer_init(buffer *buf)
{
	buf->len = buf->size = 0;
	buf->ptr = NULL;
}
*/

static void buffer_free(buffer *buf)
{
	buf->len = buf->size = 0;
	if (buf->ptr) {
		free(buf->ptr);
		buf->ptr = NULL;
	}
}

static void buffer_append(buffer *buf, const uchar *data, unsigned int len)
{
#define SIZE_ALIGN(s) (((s) + 127u) & ~127u)

	/* silly case, no data to append */
	if (!len)
		return;

	if (!buf->ptr) {
		assert(buf->size == 0 && buf->len == 0);
		buf->size = SIZE_ALIGN(len);
		buf->ptr = (uchar*) malloc(buf->size);
		if (!buf->ptr)
			fatal("memory error");
	} else {
		unsigned int new_size = SIZE_ALIGN(buf->len + len);
		if (new_size > buf->size) {
			if (!(buf->ptr = (uchar*) realloc(buf->ptr, new_size)))
				fatal("memory error");
			buf->size = new_size;
		}
	}
	memcpy(buf->ptr + buf->len, data, len);
	buf->len += len;
	assert(buf->len <= buf->size);
#undef SIZE_ALIGN
}

/*
 * Mangling / unmangling data to avoid problematic characters
 */

#define GETBIT(v,n) ((v[(n)/8] >> ((n)&7)) & 1)
#define SETBIT(v,n,bit) v[(n)/8] = ((v[(n)/8] & ~(1<<((n)&7))) | ((bit) << ((n)&7)))

static unsigned int mangle(uchar* in, unsigned int len)
{
	unsigned int n = len * 8;
	int i;
	for (i = (len+6)/7; --i >= 0; )
		in[len+i] = 0;
	for (i = n-1; i > 0; i -= 8) {
		SETBIT(in, n, GETBIT(in, i));
		++n;
		if ((n & 7) == 7)
			++n;
	}
	n = (n+7)/8;
	for (i = 0; i < n; ++i) {
		in[i] &= 0x7f;
		if (in[i] < 32)
			in[i] |= 0x80;
	}
	return n;
}

static unsigned int demangle(uchar* in, unsigned char len)
{
	unsigned int l = (7u*len) / 8, n = l *8;
	int i;
	for (i = 0; i < len; ++i)
		in[i] &= 0x7f;
	for (i = n - 1; i > 0; i -= 8) {
		SETBIT(in, i, GETBIT(in, n));
		++n;
		if ((n & 7) == 7)
			++n;
        }
	return l;
}

/*
 * Functions to handle commands
 */

static int get_int(uchar *s)
{
	return (((int) s[0]) << 24) | (((int) s[1]) << 16) | (((int) s[2]) << 8) | ((int) s[3]);
}

static void put_int(uchar *d, int i)
{
	d[0] = (i >> 24) & 0xff;
	d[1] = (i >> 16) & 0xff;
	d[2] = (i >>  8) & 0xff;
	d[3] = (i >>  0) & 0xff;
}

static void mywrite(int fd, const uchar *data, unsigned int len)
{
	int n = len;
	ssize_t res;
	
	/* do not send empty data or data to disconnected socket */
	if (!len || fd < 0)
		return;
	
	debug("writing %u bytes to fd %d", len, fd);
	debug_dump(NULL, data, len);
	while (n > 0) {
		do {
			res = write(fd, data, n);
		} while(res < 0 && errno == EINTR);
		if (res <= 0 || res >= n)
			break;
		data += res;
		n -= res;
		sleep(1);
	}
}

static void dont_block(int fd)
{
	unsigned long blocking = 1;

	/* set socket to no-blocking */
	if (ioctl(fd, FIONBIO, &blocking) < 0)
		fatal("ioctl: %s", strerror(errno));
}

static void sendCommand(int fd, CommandType type, int channel, int port)
{
	uchar pack[32];
	unsigned int l;

	pack[2] = 0;	/* channel data == 0, control */
	pack[3] = type;
	pack[4] = channel;
	pack[5] = port >> 8;
	pack[6] = port & 0xff;
	l = mangle(pack + 2, 5);

	pack[0] = magic;
	pack[1] = 32 + l;
	mywrite(fd, pack, l + 2);
}

/*
 * Channels utility
 */

static channel* getChannel(ChannelType type, int n, int fd)
{
	int i;
	channel *ch;

	if (!n) {
		for (i = 1; i <= 254; ++i) {
			if (channels[i].type == Free ) {
				n = i;
				break;
			}
		}
	}
	if (!n)
		return NULL;

	if (n < 1 || n > 254)
		fatal("Invalid channel number");

	ch = &channels[n];
	if (ch->type != Free)
		fatal("channel %d should be free", n);

	ch->type = type;
	ch->number = n;
	ch->fd = fd;
	ch->connected = 0;
	ch->blocked = 0;
	ch->remote_blocked = 0;
	ch->accepted = -1;
	ch->local = 0;
	ch->remote = 0;
	return ch;
}

static void deleteChannel(int n)
{
	channel *ch;

	if (n < 0 || n > 255)
		return;

	ch = &channels[n];
	if (ch->fd > 0) {
		close(ch->fd);
		ch->fd = -1;
	}
	buffer_free(&ch->buf);
	ch->type = Free;
}

/* initialize all channels */
static void initChannels(void)
{
	FOREACH_CHANNEL_BEGIN
		if (ch->type == Listen) {
			struct sockaddr_in sin;
			
			ch->fd = socket(PF_INET, SOCK_STREAM, 0);
			if (ch->fd < 0)
				fatal("socket: %s", strerror(errno));

			sin.sin_family = AF_INET;
			sin.sin_port = htons(ch->local);
			sin.sin_addr.s_addr = INADDR_ANY;
			if (bind(ch->fd, &sin, sizeof(sin)))
				fatal("bind: %s", strerror(errno));
			if (listen(ch->fd, 5))
				fatal("listen: %s", strerror(errno));
		}
	FOREACH_CHANNEL_END
}

static void sendInitChannels(void)
{
	FOREACH_CHANNEL_BEGIN
		if (ch->type == RemoteListen) {
			debug("send listen request for port %d", ch->remote);
			sendCommand(WRITE, CmdListen, ch->number, ch->remote);
		}
	FOREACH_CHANNEL_END
}

static int channelsSelect(int max_fd, fd_set *fds_read, fd_set *fds_write, fd_set *fds_error)
{
	int res;

	FOREACH_CHANNEL_BEGIN
		if (ch->type == Listen && ch->accepted < 0) {
			FD_SET(ch->fd, fds_read);
			if (ch->fd > max_fd) max_fd = ch->fd;
		} else if (ch->type == Connected && ch->connected) {
			if (!ch->blocked) {
				FD_SET(ch->fd, fds_read);
				FD_SET(ch->fd, fds_error);
				if (ch->fd > max_fd) max_fd = ch->fd;
			}
			if (ch->buf.len) {
				FD_SET(ch->fd, fds_write);
				if (ch->fd > max_fd) max_fd = ch->fd;
			}
		}
	FOREACH_CHANNEL_END

	res = select(max_fd + 1, fds_read, fds_write, fds_error, NULL);
	if (res < 0) {
		if (errno != EINTR)
			fatal("select error %s", strerror(errno));
		return res;
	}

	FOREACH_CHANNEL_BEGIN
		if (ch->type == Listen && ch->accepted < 0) {
			if (FD_ISSET(ch->fd, fds_read)) {
				if (client) {
					/* get a new channel to send to server */
					channel *och = getChannel(Connected, 0, -1);
					if (!och)
						fatal("No more channels");
					och->fd = accept(ch->fd, NULL, 0);
					if (och->fd < 0)
						fatal("accept %s", strerror(errno));
					dont_block(och->fd);
					if (initialized) {
						sendCommand(WRITE, CmdConnect, och->number, ch->remote);
					} else {
						deleteChannel(och->number);
					}
				} else {
					ch->accepted = accept(ch->fd, NULL, 0);
					if (ch->accepted < 0)
						fatal("accept %s", strerror(errno));
					dont_block(ch->accepted);
					sendCommand(STDOUT, CmdConnect, ch->number, 0);
				}
			}
		} else if (ch->type == Connected && ch->connected) {
			if (FD_ISSET(ch->fd, fds_write))
				write_channel_data(ch, NULL, 0);
			if (FD_ISSET(ch->fd, fds_read)) {
				ssize_t res;
				int out_fd = client ? WRITE : STDOUT;
				uchar data[128 + 3];
				unsigned int l;

				/* we tested with select for data so this can't block and must return some data */
				do {
					res = read(ch->fd, data + 3, 64);
				} while (res < 0 && errno == EINTR);
				if (res <= 0) {
					/* connection closed, send close command */
					deleteChannel(ch->number);
					sendCommand(out_fd, CmdClose, ch->number, 0);
				} else {
					data[2] = ch->number;
					l = mangle(data+2, res+1);
					data[0] = magic;
					data[1] = l + 32; /* 32 to avoid strange chars, just length */
					mywrite(out_fd, data, l + 2);
				}
			}
		}
	FOREACH_CHANNEL_END

	return res;
}

/*
 * Functions for parameters handling
 */

static void addLocal(const char *arg)
{
	int local, remote;
	channel *ch;
	
	if (sscanf(arg, "%d::%d", &local, &remote) != 2)
		fatal("invalid local syntax");
	if (remote <= 0 || remote > 65535 || local <= 0 || local > 65535)
		fatal("invalid port specification");
	
	ch = getChannel(Listen, 0, -1);
	if (!ch)
		fatal("no more channels");
	ch->local = local;
	ch->remote = remote;
	ch->blocked = 0;
}

static void addRemote(const char *arg)
{
	int remote, local, a, b, c, d;
	char ip[128];
	channel *ch;

	if (sscanf(arg, "%d::%d", &remote, &local) == 2) {
		strcpy(ip, "127.0.0.1");
	} else {
		char *start, *end;
	
		start = strchr(arg, ':');
		end = start ? strchr(start + 1, ':') : NULL;
		if (!end || (end - start) >= sizeof(ip) || sscanf(arg,"%d:", &remote) != 1 || sscanf(end, ":%d", &local) != 1)
			fatal("invalid remote syntax");
		++start;
		memcpy(ip, start, end - start);
		ip[end - start] = 0;
	}
	if (remote <= 0 || remote > 65535 || local <= 0 || local > 65535)
		fatal("invalid port specification");
	if (sscanf(ip, "%d.%d.%d.%d", &a, &b, &c, &d) != 4 || a < 0 || a > 255 || b < 0 || b > 255 || c < 0 || c > 255 || d < 0 || d > 255)
		fatal("invalid ip format");
	ch = getChannel(RemoteListen, 0, -1);
	if (!ch)
		fatal("no more channels");
	ch->local = local;
	ch->remote = remote;
	ch->ip = inet_addr(ip);
}

/*
 * Parsing functions
 */
static void write_channel_data(channel *ch, uchar *data, unsigned int len)
{
	int out_fd = client ? WRITE : STDOUT;

	if (ch->buf.len) {
		buffer_append(&ch->buf, data, len);
		data = ch->buf.ptr;
		len = ch->buf.len;
	}
	/* try to write as much data as we can */
	while (len) {
		ssize_t res;
		do {
			res = send(ch->fd, data, len, 0);
		} while (res < 0 && errno == EINTR);
		if (res < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				debug("some data left ch %d fd %d bytes %u", ch->number, ch->fd, len);
				if (data != ch->buf.ptr)
					buffer_append(&ch->buf, data, len);
				break;
			}
			if (errno != EPIPE)
				fatal("send: %s", strerror(errno));
		} else {
			debug("written %d (0x%x) bytes to fd %d", res, res, ch->fd);
			debug_dump(NULL, data, res);
			len -= res;
			memmove(data, data + res, len);
			if (data == ch->buf.ptr)
				ch->buf.len = len;
		}
	}

	/* if we reach limit send block command */
	if (!ch->remote_blocked && ch->buf.len >= BLOCK_DATA_LIMIT) {
		debug("blocking data arrival ch %d fd %d", ch->number, ch->fd);
		sendCommand(out_fd, CmdBlockData, ch->number, 1);
		ch->remote_blocked = 1;
	}

	/* if we are low the limit send unblock command */
	if (ch->remote_blocked && ch->buf.len < UNBLOCK_DATA_LIMIT) {
		debug("unblocking data arrival ch %d fd %d", ch->number, ch->fd);
		sendCommand(out_fd, CmdBlockData, ch->number, 0);
		ch->remote_blocked = 0;
	}
		
	/* free buffer if unneeded */
	if (!ch->buf.len)
		buffer_free(&ch->buf);
}

static void parseControl(void)
{
	int och;
	uchar type;
	int port;
	channel *ch;
	struct sockaddr_in sin;

	control_len = 2 + demangle(control + 2, control_len - 2);

	/* just data, channel != 0 */
	if (control[2] != 0) {
		ch = &channels[control[2]];
		/* avoid sending data to closed sockets */
		if (ch->type == Connected && ch->fd >= 0)
			write_channel_data(ch, control + 3, control_len - 3);
		return;
	}

	type = control[3];
	och  = control[4];
	port = (((int) control[5]) << 8) | control[6];

	/* command */
	switch (type) {
	case CmdListen:
		/* (only server) */
		if (client)
			break;
		/* add channel, open listening socket */
		ch = getChannel(Listen, och, -1);
		if (!ch)
			fatal("No more channels");
		debug("listen request channel %d port %d", och, port);
		ch->local = port;
		ch->fd = socket(PF_INET, SOCK_STREAM, 0);
		if (ch->fd < 0)
			fatal("socket: %s", strerror(errno));

		sin.sin_family = AF_INET;
		sin.sin_port = htons(ch->local);
		sin.sin_addr.s_addr = INADDR_ANY;

		if (bind(ch->fd, &sin, sizeof(sin)))
			fatal("bind: %s", strerror(errno));
		if (listen(ch->fd, 5))
			fatal("listen: %s", strerror(errno));
		break;

	case CmdConnect:
		debug("\nconnect command channel %d port %d\n", och, port);
		if (client) {
			/* open a new channel to connect */
			ch = getChannel(Connected, 0, -1);
			if (!ch)
				fatal("No more channels");
			port = channels[och].local;

			ch->fd = socket(PF_INET, SOCK_STREAM, 0);
			if (ch->fd < 0)
				fatal("socket: %s", strerror(errno));

			sin.sin_family = AF_INET;
			sin.sin_port = htons(port);
			sin.sin_addr.s_addr = channels[och].ip;

			if (!connect(ch->fd, &sin, sizeof(sin))) {
				debug("\nconnection request accepted\n");
				dont_block(ch->fd);
				sendCommand(WRITE, CmdAccept, och, ch->number);
				ch->connected = 1;
			} else {
				debug("\nconnection request refused\n");
				deleteChannel(ch->number);
				sendCommand(WRITE, CmdAccept, och, 0);
			}
		} else {
			ch = getChannel(Connected, och, -1);
			if (!ch)
				fatal("No more channels");
			ch->fd = socket(PF_INET, SOCK_STREAM, 0);
			if (ch->fd < 0)
				fatal("socket: %s", strerror(errno));

			sin.sin_family = AF_INET;
			sin.sin_port = htons(port);
			sin.sin_addr.s_addr = inet_addr("127.0.0.1");

			if (!connect(ch->fd, &sin, sizeof(sin))) {
				debug("connected to port %d", port);
				dont_block(ch->fd);
				sendCommand(STDOUT, CmdAccept, och, och);
				ch->connected = 1;
			} else {
				debug("error connecting to port %d", port);
				deleteChannel(ch->number);
				sendCommand(STDOUT, CmdAccept, och, 0);
			}
		}
		break;

	case CmdAccept:
		/* accept */
		if (client) {
			if (!port) {
				deleteChannel(och);
			} else {
				debug("client: accepted connection");
				channels[och].connected = 1;
			}
		} else {
			debug("accept from client");
			if (!port) {
				/* close socket */
				close(channels[och].accepted);
			} else {
				port &= 0xff;	/* avoid overflow */
				/* init new channel */
				ch = getChannel(Connected, port, -1);
				if (!ch)
					fatal("No more channels");
				/* copy socket */
				ch->fd = channels[och].accepted;
				/* set connected */
				ch->connected = 1;
			}
			/* unblock listen, accept more connections */
			channels[och].accepted = -1;
		}
		break;

	case CmdClose:
		/* close channel and related socket */
		debug("connection closed");
		deleteChannel(och);
		break;

	case CmdWindowChanged:
		/* only server */
		if (client)
			break;
		if (!initialized) {
			initialized = 1;
			while (write(WRITE, "i", 1) < 0 && errno == EINTR);
		}
		/* TODO only for TTY */
		pty_change_window_size(WRITE, get_int(&control[ 4]),
				       get_int(&control[ 8]), get_int(&control[12]),
				       get_int(&control[16]));
		break;

	case CmdBlockData:
		ch = &channels[och];
		if (ch->type == Connected)
			ch->blocked = port;
		break;

	case CmdShutdown:
		/* deinitialize */
		if (client) {
			/* close all open channels */
			FOREACH_CHANNEL_BEGIN
				if (ch->type != Free && ch->accepted > 0) {
					close(ch->accepted);
					ch->accepted = -1;
				}
				if (ch->type == Connected)
					deleteChannel(ch - channels);
			FOREACH_CHANNEL_END

			initialized = 0;
		}
		break;
	}
}

static unsigned int process(uchar *data, unsigned int len)
{
	uchar c, *p, *pend;
	uchar arg[MAX_DATA_LEN + MAX_CONTROL_LEN];
	uchar res[MAX_DATA_LEN], *pdst;
	int controlLen = 0;
	int magicInitPos = 0, magicCharCount = 0;
	
	pdst = res;
	assert(len <= MAX_DATA_LEN);
	assert(control_len >= 0 && control_len <= MAX_CONTROL_LEN); 
	if (control_len) {
		debug("some control bytes left len=%d (0x%x)", control_len, control_len);
		debug_dump(NULL, control, control_len);
	}
	memcpy(arg, control, control_len);
	memcpy(arg + control_len, data, len);
	
	pend = arg + control_len + len;

	control_len = 0;

	for (p = arg; p < pend; ++p) {
		c = *p;
		if (control_len) {
			control[control_len++] = c;
			if (control_len == controlLen) {
				int n = c;
				/* detect required length */
				if (controlLen == 2) {
					debug("got control n=%d (0x%x)\n", n, n);
					n -= 32;
					if (n < 0) n = 0;
					/* it's just a magic character quoted ?? */
					if (n == 0) {
						*pdst++ = magic;
						control_len = 0;
						continue;
					}
					controlLen = n + 2;
					continue;
				}
				debug("parsing control...\n");
				parseControl();
				control_len = 0;
			}
			continue;
		}
		if (client && magicInitPos >= MAGIC_PREFIX_LEN) {
			if (c == magicInit[magicInitPos - MAGIC_PREFIX_LEN]) {
				if (++magicInitPos == strlen(magicInit) + MAGIC_PREFIX_LEN) {
					int n;

					/* initialize remote */
					debug("Got initialization request\n");
					sendInitChannels();
					initialized = 1;
					window_changed = 1;
					check_window_change();

					/* remove magic stuff from results */
					n = magicInitPos - 1;
					if (n > pdst - res)
						n = pdst - res;
					pdst -= n;
					magicInitPos = 0;
					continue;
				}
			} else {
				magicInitPos = 0;
			}
		}
		if (c == magic) {
			if (++magicCharCount >= MAGIC_PREFIX_LEN)
				magicInitPos = MAGIC_PREFIX_LEN;
			if (!client || initialized) {
				controlLen = 2;
				control[0] = c;
				control_len = 1;
				continue;
			}
		} else {
			magicCharCount = 0;
		}
		*pdst++ = c;
	}
	assert(pdst - res <= MAX_DATA_LEN);
	memcpy(data, res, pdst - res);
	return pdst - res;
}

static void write_data(int fd, const uchar* data, unsigned int len)
{
	const uchar c = 32;

	if (client && !initialized) {
		mywrite(fd, data, len);
		return;
	}

	for (;;) {
		const uchar *p = (const uchar *) memchr(data, magic, len);
		if (!p) {
			mywrite(fd, data, len);
			return;
		}

		++p;
		mywrite(fd, data, p - data);
		mywrite(fd, &c, 1);
		len  -= p - data;
		data += p - data;
	}
}

/*
 * Signal handling
 */
static int signal_exit;
static int child_status;

static void signal_stop(int sig)
{
	signal_exit = sig;
	must_quit = 1;
}

static void signal_child(int sig)
{
	int save_errno = errno, status;
	pid_t pid;

	signal_exit = sig;

	while ((pid = waitpid(-1, &status, WNOHANG)) > 0 ||
	       (pid < 0 && errno == EINTR))
	{
		if (pid <= 0)
			continue;
		if (WIFEXITED(status) || WIFSIGNALED(status)) {
			debug("child exited");
			child_exited = 1;
			child_status = status;
			break;
		}
		signal(SIGCHLD, signal_child);
	}

	errno = save_errno;
}

static void signal_window_change(int sig)
{
	window_changed = 1;
	signal(SIGWINCH, signal_window_change);
}

static void check_window_change(void)
{
	uchar pack[64];
	unsigned int l;
	struct winsize ws;

	if (!window_changed)
		return;
	window_changed = 0;

	if (ioctl(fileno(stdin), TIOCGWINSZ, &ws) < 0) {
		ws.ws_row = 25;
		ws.ws_col = 80;
		ws.ws_xpixel = 80 * 8;
		ws.ws_ypixel = 25 * 8;
	}
	ioctl(WRITE, TIOCSWINSZ, &ws);

	if (!initialized)
		return;

	pack[2] = 0;    /* channel data == 0, control */
	pack[3] = CmdWindowChanged;
	put_int(&pack[ 4], ws.ws_row);
	put_int(&pack[ 8], ws.ws_col);
	put_int(&pack[12], ws.ws_xpixel);
	put_int(&pack[16], ws.ws_ypixel);
	l = mangle(pack + 2, 18);

	pack[0] = magic;
	pack[1] = 32 + l;
	mywrite(WRITE, pack, l + 2);
}

static int channel_options = 0;

static int parse_arguments(int argc, char **argv)
{
	int i;
	char* arg;
	char **end_no_options;
	
	/* if argv[0] == shserver default server */
	arg = strrchr(argv[0], '/');
	if (!arg)
		arg = argv[0];
	else
		++arg;
	if (strncmp(arg, "shserver", 8) == 0)
		client = 0;


	/* TODO parameter for log, magic change (warning for unsafe chars) */
	end_no_options = argv + 1;
	for (i = 1; i < argc; ++i) {
		arg = argv[i];
		if (arg[0] != '-') {
			*end_no_options++ = arg;
			continue;
		}
		++arg;
		if (!arg[0] || strcmp(arg, "-") == 0) {
			while (++i < argc)
				*end_no_options++ = argv[i];
			break;
		} else if (strcmp(arg, "L") == 0) {
			if (++i >= argc) fatal("argument expected for -L");
			addLocal(argv[i]);
			channel_options = 1;
		} else if (strcmp(arg, "R") == 0) {
			if (++i >= argc) fatal("argument expected for -R");
			addRemote(argv[i]);
			channel_options = 1;
		} else if (strcmp(arg, "-server") == 0) {
			client = 0;
		} else if (strcmp(arg, "-shell") == 0) {
			if (++i >= argc) fatal("argument expected for --shell");
			shellCmd = argv[i];
		} else if (strcmp(arg, "-debug") == 0) {
			debugEnabled = 1;
		} else if (strcmp(arg, "-log-file") == 0) {
			if (++i >= argc) fatal("argument expected for --log-file");
			logFile = argv[i];
		} else if (strcmp(arg, "-help") == 0) {
			fprintf(stderr, "Usage: shtunnel [OPTION] .. [server] [ARG] ..\n"
				"Options:\n"
				" --server                  act as server\n"
				" --shell <cmd>             specify shell command\n"
				" -L <port>::<port>         redirect (see ssh(1))\n"
				" -R <port>:[<ip>]:<port>   redirect (see ssh(1))\n"
				" --debug                   write debug info to log.txt\n"
				" --log-file <name>         file name to log to\n"
				" --help                    this help\n"
				" --version                 print version information\n"
				" --                        stop option parsing\n");
			exit(0);
		} else if (strcmp(arg, "-version") == 0) {
			fprintf(stderr, "shtunnel " VERSION "\n"
				"Copyright (C) 2004-2006 Frediano Ziglio\n"
				"This is free software; see the source for copying conditions.  There is NO\n"
				"warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.\n");
			exit(0);
		} else {
			fatal("unrecognized option '-%s'\n", arg);
		}
	}
	return end_no_options - argv;
}

static size_t quote_argument(char *dest, const char *arg)
{
	char *pdst = dest;

	if (!dest) {
		size_t len = 2;

		for (;*arg; ++arg, ++len)
			if (strchr("$\"`\\", *arg))
				++len;
		return len;
	}

	*pdst++ = '\"';
	for (;*arg; ++arg) {
		if (strchr("$\"`\\", *arg))
			*pdst++ = '\\';
		*pdst++ = *arg;
	}
	*pdst++ = '\"';
	*pdst = 0;
	return pdst - dest;
}

static size_t quote_arguments(char *dest, char **args, int num_arg)
{
	char *pdst = dest;
	int i;

	if (!dest) {
		size_t len = num_arg;
		for (i = 0; i < num_arg; ++i)
			len += quote_argument(NULL, args[i]);
		return len;
	}

	for (i = 0; i < num_arg; ++i) {
		*pdst++ = ' ';
		pdst += quote_argument(pdst, args[i]);
	}
	*pdst = 0;
	return pdst - dest;
}

int main(int argc, char **argv)
{
	char *p;
	int ptyfd = -1, ttyfd = -1, i;
	char ttyname[128];
	int READ = -1, READ2 = -1;
	int STDIN  = 0;
	int pipes[6], num_pipe = 0;

	argc = parse_arguments(argc, argv);

	if (client) {
		if (argc < 2)
			fatal("server option needed");
		strcpy(endPoint, "client");
		
		if (!shellCmd)
			shellCmd = "ssh";

		initChannels();
	} else {
		if (channel_options) {
			fprintf(stderr, "channel options ignored on server\n");
			fflush(stderr);
			memset(channels, 0, sizeof(channels));
		}
		strcpy(endPoint, "server");

		/* get user shell*/
		if (!shellCmd) {
			struct passwd *pw = getpwuid(getuid());
			shellCmd = strdup(pw->pw_shell);
		}
	}

	/* handle redirections creating pipe where no tty */
	for (i = 0; i < 6; ++i)
		pipes[i] = -1;
	for (i = 0; i < 3; ++i) {
		if (isatty(i))
			continue;
		if (pipe(pipes+i*2))
			fatal("pipe");
		++num_pipe;
	}
	/* allocate a pty if we want at least one tty */
	if (num_pipe < 3 && !pty_allocate(&ptyfd, &ttyfd, ttyname, sizeof(ttyname)))
		fatal("creating pty");

	/* TODO only if TTY, not for pipe... pass parameter for file to allow input redirection */
	enter_raw_mode();

	/* init request must be send after switching to raw to avoid echo */
	if (!client) {
		uchar buf[MAGIC_PREFIX_LEN + sizeof(magicInit)];

		memset(buf, magic, MAGIC_PREFIX_LEN);
		memcpy(buf + MAGIC_PREFIX_LEN, magicInit, strlen(magicInit));
		mywrite(STDOUT, buf, MAGIC_PREFIX_LEN + strlen(magicInit));
	}

	signal(SIGPIPE, SIG_IGN);
	signal(SIGCHLD, signal_child);

	/* TODO on exit close child and reset terminal */
	switch(fork()) {
	case 0:
		/* close all listen sockets */
		FOREACH_CHANNEL_BEGIN
			if (ch->type == Listen && ch->fd >= 0)
				close(ch->fd);
		FOREACH_CHANNEL_END

		/* from openssh session.c */
		if (ttyfd >= 0) {
			close(ptyfd);
			pty_make_controlling_tty(&ttyfd, ttyname);
		}

		/* replace files */
		for (i = 0; i < 3; ++i) {
			static const char names[3][4] = { "in", "out", "err" };
			int fd;

			if (isatty(i)) {
				fd = ttyfd;
			} else {
				fd = pipes[i*2+(i==0?0:1)];
				close(pipes[i*2+(i==0?1:0)]);
			}
			if (dup2(fd, i) < 0)
				error("dup2 std%s: %s", names[i], strerror(errno));
		}
		if (ttyfd >= 0)
			close(ttyfd);

		leave_raw_mode();

		/* wait initialization */
		enter_raw_mode();
		if (!client) {
			char c;
			ssize_t len;
			while ((len = read(0, &c, 1)) < 0 && errno == EINTR);
			if (len <= 0)
				return 1;
		}
		leave_raw_mode();

		/* TODO parse parameters instead of using an extra shell */
		p = malloc(strlen(shellCmd) + quote_arguments(NULL, argv + 1, argc - 1) + 10);
		strcpy(p, shellCmd);
		quote_arguments(strchr(p, 0), argv + 1, argc - 1);
		execlp("sh", "sh", "-c", p, NULL);
		return 1;
		break;
	case -1:
		fatal("fork error");
	}
	if (ttyfd >= 0)
		close(ttyfd);

	if (isatty(0)) {
		WRITE = ptyfd;
	} else {
		WRITE = pipes[1];
		close(pipes[0]);
	}

	if (isatty(1)) {
		READ = dup(ptyfd);
		if (READ < 0)
			fatal("duplicating pty");
	} else {
		READ = pipes[2];
		close(pipes[3]);
	}

	if (isatty(2)) {
		if (!isatty(1)) {
			READ2 = dup(ptyfd);
			if (READ2 < 0)
				fatal("duplicating pty");
		}
	} else {
		READ2 = pipes[4];
		close(pipes[5]);
	}

	signal(SIGINT, signal_stop);
	signal(SIGQUIT, signal_stop);
	signal(SIGTERM, signal_stop);

	if (client) {
		/* TODO only for TTY */
		signal(SIGWINCH, signal_window_change);

		window_changed = 1;
	}

	control_len = 0;

	for (;;) {
		fd_set fds_read, fds_write, fds_error;
		int max_fd = 0;

		FD_ZERO(&fds_read);
		if (STDIN >= 0)
			FD_SET(STDIN, &fds_read);
		if (READ >= 0)
			FD_SET(READ, &fds_read);
		if (READ2 >= 0)
			FD_SET(READ2, &fds_read);

		FD_ZERO(&fds_write);

		FD_ZERO(&fds_error);
		if (READ >= 0)
			FD_SET(READ, &fds_error);
		if (READ2 >= 0)
			FD_SET(READ2, &fds_error);
		FD_SET(WRITE, &fds_error);

		if (STDIN > max_fd) max_fd = STDIN;
		if (READ > max_fd) max_fd = READ;
		if (READ2 > max_fd) max_fd = READ2;
		if (WRITE > max_fd) max_fd = WRITE;

		if (must_quit || (child_exited && READ < 0))
			break;
		check_window_change();

		if (channelsSelect(max_fd, &fds_read, &fds_write, &fds_error) < 0)
			continue;

		if (must_quit || (child_exited && READ < 0))
			break;
		check_window_change();

		if (READ >= 0 && FD_ISSET(READ, &fds_error))
			fatal("READ");
		if (FD_ISSET(WRITE, &fds_error))
			fatal("WRITE");

		if (STDIN >= 0 && FD_ISSET(STDIN, &fds_read)) {
			uchar data[MAX_DATA_LEN];
			ssize_t res = read(STDIN, data, MAX_DATA_LEN);
			if (res <= 0) {
				/* this can be caused by redirection of standard input on client */
				if (client) {
					/* TODO perhaps we should close server side too */
					close(STDIN);
					STDIN = -1;
					continue;
				} else {
					fatal("broken pipe input %s", endPoint);
				}
			}
			debug_dump(client ? "data from input" : "data from client", data, res);
			if (client) {
				write_data(WRITE, data, res);
			} else {
				res = process(data, res);
				/* TODO if not initialized we should not write data but buffer and send when ready */
				/* use blocking socket ?? */
				mywrite(WRITE, data, res);
			}
		}

		if (READ >= 0 && FD_ISSET(READ, &fds_read)) {
			uchar data[MAX_DATA_LEN];
			ssize_t res = read(READ, data, MAX_DATA_LEN);
			if (res <= 0) {
				debug("broken pipe %s", endPoint);

				/* this can be caused by program termination */
				if (client)
					must_quit = 1;
				close(READ);
				READ = -1;
				continue;
			}
			debug_dump(client ? "data from server" : "data from program", data, res);
			if (client) {
				res = process(data, res);
				mywrite(STDOUT, data, res);
			} else {
				write_data(STDOUT, data, res);
			}
		}
		if (READ2 >= 0 && FD_ISSET(READ2, &fds_read)) {
			uchar data[MAX_DATA_LEN];
			ssize_t res = read(READ2, data, MAX_DATA_LEN);
			if (res <= 0) {
				close(READ2);
				READ2 = -1;
				continue;
			}
			debug_dump(client ? "data from server" : "data from program", data, res);
			mywrite(STDERR, data, res);
		}
	}

	if (!client)
		sendCommand(STDOUT, CmdShutdown, 0, 0);
	leave_raw_mode();

	/* pass code from child process */
	if (signal_exit == SIGCHLD) {
		if (WIFEXITED(child_status))
			return WEXITSTATUS(child_status);
		if (WIFSIGNALED(child_status))
			return 1;
	}

	return 0;
}
