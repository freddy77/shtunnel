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
#include "sshpty.h"

typedef unsigned char uchar;

#define MAGIC "\xf0"
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
	CmdListen = 51,
	CmdConnect,
	CmdAccept,
	CmdClose,
	CmdShutdown,
	CmdWindowChanged
} CommandType;

typedef struct channel {
	ChannelType type;
	int number;
	int fd;		/* file descriptor */
	int accepted;	/* file descriptor of accepted socket */
	int local;	/* local port */
	int remote;	/* remote port */
	int blocked;
	int connected;
	in_addr_t ip;	/* address for local listen */
} channel;

static channel channels[256];
#define FOREACH_CHANNEL_BEGIN {channel *ch; for (ch = channels; ch != channels + (sizeof(channels)/sizeof(channels[0])); ++ch) {
#define FOREACH_CHANNEL_END   }}

static const char *server = NULL;
static int client = 1;
static const char *shellCmd = NULL;
static int initialized = 0;
static int debugEnabled = 0;
static char endPoint[32] = ""; /* "client" or "server" */

static int WRITE = -1;
static int READ = -1;
static const int STDOUT = 1;
static const int STDIN  = 0;

#define MAX_CONTROL_LEN 260
#define MAX_DATA_LEN 1000
static uchar control[MAX_CONTROL_LEN];
static int control_len = 0;

/* program should terminate on signal */
static volatile int must_quit;
/* program have received a windows change */
static volatile int window_changed;

static void sendCommand(int fd, CommandType type, int channel, int port);
static void check_window_change(void);

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
		log = fopen("log.txt", "a");
		if (!log)
			fatal ("Error opening log file");
	}
	va_start(ap, msg);
	vfprintf(log,  msg, ap);
	va_end(ap);
	fprintf(log, "\n");
	fflush(log);
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
		in[i/8] |= 0x80;
		if ((n & 7) == 7) {
			in[n/8] |= 0x80;
			++n;
		}
	}
	if (n & 7)
		in[n/8] |= 0x80;
	return (n+7)/8;
}

static unsigned int demangle(uchar* in, unsigned char len)
{
	unsigned int l = (7u*len) / 8, n = l *8;
	int i;
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
		if (ch->type == Listen && !ch->blocked) {
			FD_SET(ch->fd, fds_read);
			if (ch->fd > max_fd) max_fd = ch->fd;
		} else if (ch->type == Connected && ch->connected) {
			FD_SET(ch->fd, fds_read);
			FD_SET(ch->fd, fds_error);
			if (ch->fd > max_fd) max_fd = ch->fd;
		}
	FOREACH_CHANNEL_END

	res = select(max_fd + 1, fds_read, fds_write, fds_error, NULL);
	if (res < 0) {
		if (errno != EINTR)
			fatal("select error %s", strerror(errno));
		return res;
	}

	FOREACH_CHANNEL_BEGIN
		if (ch->type == Listen && !ch->blocked) {
			if (FD_ISSET(ch->fd, fds_read)) {
				if (client) {
					/* get a new channel to send to server */
					channel *och = getChannel(Connected, 0, -1);
					if (!och)
						fatal("No more channels");
					och->fd = accept(ch->fd, NULL, 0);
					if (och->fd < 0)
						fatal("accept %s", strerror(errno));
					if (initialized) {
						sendCommand(WRITE, CmdConnect, och->number, ch->remote);
					} else {
						deleteChannel(och->number);
					}
				} else {
					ch->accepted = accept(ch->fd, NULL, 0);
					if (ch->accepted < 0)
						fatal("accept %s", strerror(errno));
					ch->blocked = 1;
					sendCommand(STDOUT, CmdConnect, ch->number, 0);
				}
			}
		} else if (ch->type == Connected && ch->connected) {
			if (FD_ISSET(ch->fd, fds_read)) {
				ssize_t res;
				int out_fd = client ? WRITE : STDOUT;
				uchar data[128 + 3];
				unsigned int l;

				do { 
					res = read(ch->fd, data + 3, 64);
				} while (res < 0 && errno == EINTR);
				if (!res) {
					/* connection closed, send close command */
					deleteChannel(ch->number);
					sendCommand(out_fd, CmdClose, ch->number, 0);
				} else {
					data[0] = magic;
					data[1] = res + 32;
					data[2] = ch->number;
					l = mangle(data+2, res+1);
					data[1] = l + 32; /* 32 to avoid strange chars, just length */
					l += 2;
					mywrite(out_fd, data, l);
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

static void parseControl(void)
{
	int och;
	uchar type;
	int port;
	channel *ch;
	struct sockaddr_in sin;

	/* FIXME possible buffer overflow */
	control_len = 2 + demangle(control + 2, control_len - 2);

	/* just data, channel != 0 */
	if (control[2] != 0) {
		ch = &channels[control[2]];
		mywrite(ch->fd, control + 3, control_len - 3);
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
				ch->connected = 1;
				debug("\nrichiesta connessione accettata\n");
				sendCommand(WRITE, CmdAccept, och, ch->number);
			} else {
				debug("\nrichiesta connessione rifiutata\n");
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
			channels[och].blocked = 0;
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
		/* TODO only for TTY */
		pty_change_window_size(WRITE, get_int(&control[ 4]),
				       get_int(&control[ 8]), get_int(&control[12]),
				       get_int(&control[16]));
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
	memcpy(arg, control, control_len);
	memcpy(arg + control_len, data, len);
	
	control_len = 0;

	pend = arg + control_len + len;
	for (p = arg; p < pend; ++p) {
		c = *p;
		if (control_len) {
			control[control_len++] = c;
			if (control_len == controlLen) {
				int n = c;
				/* detect required length */
				if (controlLen == 2) {
					debug("got control n=%d\n", n);
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
					/* initialize remote */
					debug("Got initialization request\n");
					sendInitChannels();
					initialized = 1;
					window_changed = 1;
					check_window_change();
				}
			} else {
				magicInitPos = 0;
			}
		}
		if (c == magic) {
			if (++magicCharCount >= MAGIC_PREFIX_LEN)
				magicInitPos = MAGIC_PREFIX_LEN;
			if (initialized) {
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
	memcpy(data, res, pdst - res);
	return pdst - res;
}

/*
 * Signal handling
 */

static void signal_stop(int sig)
{
	must_quit = 1;
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

	if (ioctl(fileno(stdin), TIOCGWINSZ, &ws) < 0)
		return;
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

int main(int argc, char **argv)
{
	int i;
	const char* arg;
	char *p;
	int ptyfd, ttyfd;
	char ttyname[128];
	int channel_options = 0;

	/* if argv[0] == shserver default server */
	arg = strrchr(argv[0], '/');
	if (!arg)
		arg = argv[0];
	else
		++arg;
	if (strncmp(arg, "shserver", 8) == 0)
		client = 0;

	/* TODO parameter for log, magic change (warning for unsafe chars) */
	for (i = 1; i < argc; ++i) {
		arg = argv[i];
		if (strcmp(arg, "-L") == 0) {
			if (++i >= argc) fatal("argument expected");
			addLocal(argv[i]);
			channel_options = 1;
		} else if (strcmp(arg, "-R") == 0) {
			if (++i >= argc) fatal("argument expected");
			addRemote(argv[i]);
			channel_options = 1;
		} else if (strcmp(arg, "--server") == 0) {
			client = 0;
		} else if (strcmp(arg, "--shell") == 0) {
			if (++i >= argc) fatal("argument expected");
			shellCmd = argv[i];
		} else if (strcmp(arg, "--debug") == 0) {
			debugEnabled = 1;
		} else if (strcmp(arg, "--help") == 0) {
			fprintf(stderr, "Usage: shtunnel [options] [server]\n"
				"Options:\n"
				" --server                  act as server\n"
				" --shell <cmd>             specify shell command\n"
				" -L <port>::<port>         redirect (see ssh(1))\n"
				" -R <port>:[<ip>]:<port>   redirect (see ssh(1))\n");
			return 0;
		} else {
			server = arg;
		}
	}

	fprintf(stderr, "shtunnel " VERSION "\n"
		"Copyright (C) 2004 Frediano Ziglio\n"
		"This is free software; see the source for copying conditions.  There is NO\n"
		"warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.\n");

	if (client) {
		if (!server)
			fatal("server option needed");
		strcpy(endPoint, "client");
		
		if (!shellCmd)
			shellCmd = "ssh";

		initChannels();
	} else {
		server = "";
		initialized = 1;
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

	/* TODO do not allocate a pty if from a pipe */
	/*
	 * TODO handle redirection, we must prodive a replace for stdin and stdout
	 * check minimiun available pty
	 */
	if (!pty_allocate(&ptyfd, &ttyfd, ttyname, sizeof(ttyname)))
		fatal("creating pty");

	/* TODO only if TTY, not for pipe... pass parameter for file to allow input redirection */
	enter_raw_mode();

	/* init request must be send after switching to raw to avoid echo */
	if (!client) {
		uchar buf[MAGIC_PREFIX_LEN + sizeof(magicInit)];
		int i;

		for (i = 0; i < MAGIC_PREFIX_LEN; ++i)
			buf[i] = magic;
		strcpy(buf + MAGIC_PREFIX_LEN, magicInit);
		mywrite(STDOUT, buf, MAGIC_PREFIX_LEN + strlen(magicInit));
	}

	/* TODO on exit close child and reset terminal */
	switch(fork()) {
	case 0:
		/* close all listen sockets */
		FOREACH_CHANNEL_BEGIN
			if (ch->type == Listen && ch->fd >= 0)
				close(ch->fd);
		FOREACH_CHANNEL_END

		/* from openssh session.c */
		close(ptyfd);
		pty_make_controlling_tty(&ttyfd, ttyname);

		/* replace files */
		if (dup2(ttyfd, 0) < 0)
			error("dup2 stdin: %s", strerror(errno));
		if (dup2(ttyfd, 1) < 0)
			error("dup2 stdout: %s", strerror(errno));
		if (dup2(ttyfd, 2) < 0)
			error("dup2 stderr: %s", strerror(errno));
		close(ttyfd);

		leave_raw_mode();

		/* TODO parse parameters instead of using an extra shell */
		p = malloc(strlen(server) + strlen(shellCmd) + 10);
		sprintf(p, "%s %s", shellCmd, server);
		execlp("sh", "sh", "-c", p, NULL);
		return 1;
		break;
	case -1:
		fatal("fork error");
	}
	close(ttyfd);
	READ = dup(ptyfd);
	if (READ < 0)
		fatal("duplicating pty");
	WRITE = ptyfd;

	/* TODO finish support for SIGINT SIGTERM SIGSTOP */
	signal(SIGPIPE, SIG_IGN);
	/* TODO see ssh.c for how to handle SIGINT and SIGTERM correctly */
	if (!client)
		signal(SIGINT, SIG_IGN);

	if (client) {
		signal(SIGINT, signal_stop);
		signal(SIGQUIT, signal_stop);
		signal(SIGTERM, signal_stop);

		/* TODO only for TTY */
		signal(SIGWINCH, signal_window_change);

		window_changed = 1;
	}

	control_len = 0;

	for (;;) {
		fd_set fds_read, fds_write, fds_error;
		int max_fd = 0;

		FD_ZERO(&fds_read);
		FD_SET(STDIN, &fds_read);
		FD_SET(READ, &fds_read);

		FD_ZERO(&fds_write);

		FD_ZERO(&fds_error);
		FD_SET(READ, &fds_error);
		FD_SET(WRITE, &fds_error);

		if (STDIN > max_fd) max_fd = STDIN;
		if (READ > max_fd) max_fd = READ;
		if (WRITE > max_fd) max_fd = WRITE;

		if (must_quit)
			break;
		check_window_change();

		if (channelsSelect(max_fd, &fds_read, &fds_write, &fds_error) < 0)
			continue;

		if (must_quit)
			break;
		check_window_change();

		/*
		 * TODO if no space to write do not read from channels
		 */

		if (FD_ISSET(READ, &fds_error))
			fatal("READ");
		if (FD_ISSET(WRITE, &fds_error))
			fatal("WRITE");

		if (FD_ISSET(STDIN, &fds_read)) {
			char data[MAX_DATA_LEN+1];
			ssize_t res = read(STDIN, data, MAX_DATA_LEN);
			if (res <= 0)
				fatal("broken pipe %s", endPoint);
			data[res] = 0;
			if (!client)
				debug("\nfrom client='%s'", data);
			if (!client)
				res = process(data, res);
			/* TODO quote magic */
			mywrite(WRITE, data, res);
		}

		if (FD_ISSET(READ, &fds_read)) {
			char data[MAX_DATA_LEN+1];
			ssize_t res = read(READ, data, MAX_DATA_LEN);
			if (res <= 0)
				fatal("broken pipe %s", endPoint);
			data[res] = 0;
			debug("\norig='%s'", data);
			if (client)
				res = process(data, res);
			/* TODO quote magic */
			mywrite(STDOUT, data, res);
		}
	}

	if (!client)
		sendCommand(STDOUT, CmdShutdown, 0, 0);
	leave_raw_mode();

	return 0;
}
