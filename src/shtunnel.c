#include "config.h"
#include <stdio.h>
#include <stdarg.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif

#if HAVE_SELECT_H
#include <sys/select.h>
#endif /* HAVE_SELECT_H */

#if HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif /* HAVE_SYS_SOCKET_H */

#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif /* HAVE_NETINET_IN_H */

#if HAVE_NETINET_TCP_H
#include <netinet/tcp.h>
#endif /* HAVE_NETINET_TCP_H */

#if HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif /* HAVE_ARPA_INET_H */

#ifdef HAVE_SIGNAL_H
#include <signal.h>
#endif

//#!/usr/bin/perl

//use Socket;
//use POSIX;
//#use strict;

typedef unsigned char uchar;

#define MAGIC "\xf0"
static const uchar magic = 0xF0;
static const char magicInit[] = MAGIC MAGIC MAGIC MAGIC MAGIC MAGIC "ShellTunnelInit";

typedef enum {
	Free,
	Connected,
	Listen,
	Connect
} ChannelType;

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

static const char *server = NULL;
static int client = 1;
static const char *shellCmd = "ssh -t -t";
static int initialized = 0;
//const char *sockaddr = "S n a4 x8";
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

static void die(const char *msg, ...)
{
	va_list ap;

	fprintf(stderr, "fatal error: ");

	va_start(ap, msg);
	vfprintf (stderr, msg, ap);
	va_end(ap);

	fprintf(stderr, "\n");
	exit(1);
}

static void debug(const char *msg, ...)
{
	va_list ap;
	static FILE *log = NULL;

	if (!debugEnabled)
		return;

	if (client)
		log = stdout;
	if (!log) {
		log = fopen("log.txt", "a");
		if (!log)
			die ("Error opening log file");
	}
	va_start(ap, msg);
	vfprintf(log,  msg, ap);
	va_end(ap);
	fprintf(log, "\n");
	fflush(log);
}

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
//		vec($in,$n++,1) = vec($in,$i,1);
//		vec($in,$i,1) = 1;
//		vec($in,$n++,1) = 1 if (($n&7)==7);
	}
	if (n & 7)
		in[n/8] |= 0x80;
	return (n+7)/8;
//	vec($in,$n|7,1) = 1 if ($n & 7);
//	return $in;
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
//		vec($in,$i,1) = vec($in,$n++,1);
//		$n++ if (($n&7)==7);
        }
	return l;
}

#define MAX_CMDLEN 128
static unsigned int commandPack(int type, int channel, int port, uchar *pack)
{
	pack[0] = magic;
	pack[1] = 32;
	pack[2] = type;
	pack[3] = channel;
	pack[4] = port >> 8;
	pack[5] = port & 0xff;
	return 2 + mangle(pack + 2, 4);
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
		die("Invalid channel number");

	ch = &channels[n];
	if (ch->type != Free)
		die("channel should be free");

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
	int i;
	channel *ch;

	for (i = 0; i < 256; ++i) {
		ch = &channels[i];
		if (ch->type == Listen) {
			struct sockaddr_in sin;
			
			ch->fd = socket(PF_INET, SOCK_STREAM, 0);
			if (ch->fd < 0)
				die("socket: %s", strerror(errno));

			sin.sin_family = AF_INET;
			sin.sin_port = htons(ch->local);
			sin.sin_addr.s_addr = INADDR_ANY;
			if (bind(ch->fd, &sin, sizeof(sin)))
				die("bind: %s", strerror(errno));
			if (listen(ch->fd, 5))
				die("listen: %s", strerror(errno));
		}
	}
}

static void sendInitChannels(void)
{
	int i;
	channel *ch;

	for (i = 0; i < 256; ++i) {
		ch = &channels[i];
		if (ch->type == Connect) {
			uchar cmd[MAX_CMDLEN];
			unsigned int l;

			/* TODO write all */
			debug("send listen request for port %d", ch->remote);
			l = commandPack(51, ch->number, ch->remote, cmd);
			mywrite(WRITE, cmd, l);
		}
	}
}

static void channelsSelect(int max_fd, fd_set *fds_read, fd_set *fds_write, fd_set *fds_error)
{
	int i;
	channel *ch;

	for (i = 0; i < 256; ++i) {
		ch = &channels[i];
		if (ch->type == Listen && !ch->blocked) {
			FD_SET(ch->fd, fds_read);
			if (ch->fd > max_fd) max_fd = ch->fd;
		} else if (ch->type == Connected && ch->connected) {
			FD_SET(ch->fd, fds_read);
			FD_SET(ch->fd, fds_error);
			if (ch->fd > max_fd) max_fd = ch->fd;
		}
	}

	select(max_fd + 1, fds_read, fds_write, fds_error, NULL);

	for (i = 0; i < 256; ++i) {
		ch = &channels[i];
		if (ch->type == Listen && !ch->blocked) {
			if (FD_ISSET(ch->fd, fds_read)) {
				if (client) {
					/* get a new channel to send to server */
					channel *och = getChannel(Connected, 0, -1);
					if (!och)
						die("No more channels");
					och->fd = accept(ch->fd, NULL, 0);
					if (och->fd < 0)
						die("accept %s", strerror(errno));
					if (initialized) {
						uchar cmd[MAX_CMDLEN];
						unsigned l = commandPack(52, och->number, ch->remote, cmd);
						mywrite(WRITE, cmd, l);
					} else {
						deleteChannel(och->number);
					}
				} else {
					uchar cmd[MAX_CMDLEN];
					unsigned l;

					ch->accepted = accept(ch->fd, NULL, 0);
					if (ch->accepted < 0)
						die("accept %s", strerror(errno));
					ch->blocked = 1;
					l = commandPack(52, ch->number, 0, cmd);
					mywrite(STDOUT, cmd, l);
				}
			}
		} else if (ch->type == Connected && ch->connected) {
			if (FD_ISSET(ch->fd, fds_read)) {
				ssize_t res;
				uchar data[128 + 3];
				unsigned int l;

				do { 
					res = read(ch->fd, data + 3, 64);
				} while (res < 0 && errno == EINTR);
				if (!res) {
					/* connection closed, send close command */
					deleteChannel(ch->number);
					l = commandPack(54, ch->number, 0, data);
				} else {
					data[0] = magic;
					data[1] = res + 32;
					data[2] = ch->number;
					l = mangle(data+2, res+1);
					data[1] = l + 32; /* 32 to avoid strange chars, just length */
					l += 2;
//					$r = mangle(pack('C',$ch->{number}).$r);
//					$r = pack('aC',$magic, 32+length($r)).$r;
				}
				if (client) {
					mywrite(WRITE, data, l);
				} else {
					mywrite(STDOUT, data, l);
				}
			}
		}
	}
}

static void addLocal(const char *arg)
{
	int local, remote;
	channel *ch;
	
	if (sscanf(arg, "%d::%d", &local, &remote) != 2)
		die("invalid local syntax");
	
	ch = getChannel(Listen, 0, -1);
	if (!ch)
		die("no more channels");
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
			die("invalid remote syntax");
		++start;
		memcpy(ip, start, end - start);
		ip[end - start] = 0;
	}
	if (remote <= 0 || remote > 65535 || local <= 0 || local > 65535)
		die("invalid port specification");
	if (sscanf(ip, "%d.%d.%d.%d", &a, &b, &c, &d) != 4 || a < 0 || a > 255 || b < 0 || b > 255 || c < 0 || c > 255 || d < 0 || d > 255)
		die("invalid ip format");
	ch = getChannel(Connect, 0, -1);
	if (!ch)
		die("no more channels");
	ch->local = local;
	ch->remote = remote;
	ch->ip = inet_addr(ip);
}

/*

sub echoOff 
{
	$olterm = $term->getlflag();
	$octerm = $term->getcc(VTIME);
	$term->setlflag($olterm & ~(ECHO|ECHOK|ICANON));
	$term->setcc(VTIME, 0);
	$term->setattr(fileno(STDIN), TCSANOW);
}

sub echoOn
{
	$term->setlflag($olterm);
	$term->setcc(VTIME, $octerm);
	$term->setattr(fileno(STDIN), TCSANOW);
}

sub gotoRaw
{
	my $tmp = $term->getiflag();
	$term->setiflag($tmp & ~(IGNBRK|BRKINT|PARMRK|ISTRIP|INLCR|IGNCR|ICRNL|IXON));
	$tmp = $term->getoflag();
	$term->setoflag($tmp & ~OPOST);
	$tmp = $term->getlflag();
	$term->setlflag($tmp & ~(ECHO|ECHONL|ICANON|ISIG|IEXTEN));
	$tmp = $term->getcflag();
	$term->setcflag($tmp & ~(CSIZE|PARENB) | CS8);
}

*/

static void parseControl(void)
{
	int nch, och;
	uchar type;
	int port;
	channel *ch;
	struct sockaddr_in sin;
                                                                                                                                               
//	my ($m, $nch) = unpack('aC', $control);
	nch = control[1];
	control_len -= 2;
	memmove(control, control + 2, control_len);
//	$control = demangle(substr($control,2));
	control_len = demangle(control, control_len);

	/* just data */
	if (nch != 32) {
		nch = control[0];
//		($nch) = unpack('C',$control);
//		my $ch = $channels{$nch};
		ch = &channels[nch];
		mywrite(ch->fd, control + 1, control_len - 1);
		return;
	}

	type = control[0];
	och  = control[1];
	port = (((int) control[2]) << 8) | control[3];

	/* command */
	switch (type) {
	case 51:
		/* listen (only server) */
		/* add channel, open listening socket */
		ch = getChannel(Listen, och, -1);
		if (!ch)
			die("No more channels");
		debug("listen request channel %d port %d", och, port);
		ch->local = port;
//		my $fh = $ch->{fh};
		ch->fd = socket(PF_INET, SOCK_STREAM, 0);
		if (ch->fd < 0)
			die("socket: %s", strerror(errno));
//		my $this = pack($sockaddr, &AF_INET, $ch->{'local'}, "\0\0\0\0");

		sin.sin_family = AF_INET;
		sin.sin_port = htons(ch->local);
		sin.sin_addr.s_addr = INADDR_ANY;

		if (bind(ch->fd, &sin, sizeof(sin)))
			die("bind: %s", strerror(errno));
		if (listen(ch->fd, 5))
			die("listen: %s", strerror(errno));
		break;

	case 52:
		/* connect */
		debug("\nconnect command channel %d port %d\n", och, port);
		if (client) {
			/* open a new channel to connect */
			ch = getChannel(Connected, 0, -1);
			if (!ch)
				die("No more channels");
			port = channels[och].local;

			ch->fd = socket(PF_INET, SOCK_STREAM, 0);
			if (ch->fd < 0)
				die("socket: %s", strerror(errno));

			sin.sin_family = AF_INET;
			sin.sin_port = htons(port);
			sin.sin_addr.s_addr = channels[och].ip;

			if (!connect(ch->fd, &sin, sizeof(sin))) {
				uchar cmd[MAX_CMDLEN];
				unsigned int l;
				
				ch->connected = 1;
				debug("\nrichiesta connessione accettata\n");
				l = commandPack(53, och, ch->number, cmd);
				mywrite(WRITE, cmd, l);
			} else {
				uchar cmd[MAX_CMDLEN];
				unsigned int l;

				debug("\nrichiesta connessione rifiutata\n");
				deleteChannel(ch->number);
				l = commandPack(53, och, 0, cmd);
				mywrite(WRITE, cmd, l);
			}
		} else {
			ch = getChannel(Connected, och, -1);
			if (!ch)
				die("No more channels");
			ch->fd = socket(PF_INET, SOCK_STREAM, 0);
			if (ch->fd < 0)
				die("socket: %s", strerror(errno));

			sin.sin_family = AF_INET;
			sin.sin_port = htons(port);
			sin.sin_addr.s_addr = inet_addr("127.0.0.1");

			if (!connect(ch->fd, &sin, sizeof(sin))) {
				uchar cmd[MAX_CMDLEN];
				unsigned int l;

				debug("connected to port %d", port);
				l = commandPack(53, och, och, cmd);
				mywrite(STDOUT, cmd, l);
				ch->connected = 1;
			} else {
				uchar cmd[MAX_CMDLEN];
				unsigned int l;

				debug("error connecting to port %d", port);
				deleteChannel(ch->number);
				l = commandPack(53, och, 0, cmd);
				mywrite(STDOUT, cmd, l);
			}
		}
		break;

	case 53:
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
				/* init new channel */
				ch = getChannel(Connected, port, -1);
				if (!ch)
					die("No more channels");
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

	case 54:
		/* close */
		/* close channel and related socket */
		debug("connection closed");
		deleteChannel(och);
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
//		debug("control=".join(',',unpack('C6',$control))."\n") if (length($control));
		if (control_len) {
			control[control_len++] = c;
			if (control_len == controlLen) {
				int n = c;
				/* detect required length */
				if (controlLen == 2) {
					debug("\ngot control n=%d\n", n);
					n -= 32;
					if (n < 0) n = 0;
					/* it's just a magic character quoted ?? */
					if (n == 1) {
						*pdst++ = magic;
						control_len = 0;
						continue;
					}
					controlLen = (n == 0) ? 7 : n + 2;
					continue;
				}
				debug("\nparsing control...\n");
				parseControl();
				control_len = 0;
			}
			continue;
		}
		if (client && magicInitPos >= 6) {
			if (c == magicInit[magicInitPos]) {
				if (++magicInitPos == strlen(magicInit)) {
					/* initialize remote */
					debug("\nGot initialization request\n");
					sendInitChannels();
					initialized = 1;
				}
			} else {
				magicInitPos = 0;
			}
		}
		if (c == magic) {
			if (++magicCharCount >= 6)
				magicInitPos = 6;
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

int main(int argc, char **argv)
{
	int i;
	const char* arg;
	char *p;
	int outpipes[2];
	int inpipes[2];

	for (i = 1; i < argc; ++i) {
		arg = argv[i];
		if (strcmp(arg, "-L") == 0) {
			if (++i >= argc) die("parameter expected");
			addLocal(argv[i]);
		} else if (strcmp(arg, "-R") == 0) {
			if (++i >= argc) die("parameter expected");
			addRemote(argv[i]);
		} else if (strcmp(arg, "--server") == 0) {
			client = 0;
		} else if (strcmp(arg, "--shell") == 0) {
			if (++i >= argc) die("parameter expected");
			shellCmd = argv[i];
		} else if (strcmp(arg, "--debug") == 0) {
			debugEnabled = 1;
		} else {
			server = arg;
		}
	}

	if (client) {
		if (!server)
			die("server option needed");
		strcpy(endPoint, "client");
	} else {
		server = "";
		mywrite(STDOUT, magicInit, strlen(magicInit));
		initialized = 1;
		strcpy(endPoint, "server");
	}

	initChannels();
/*
use IPC::Open2;
$pid = open2(*READ, *WRITE, "$shellCmd $server" );
select WRITE;  $| = 1;
select STDOUT; $| = 1;

$| = 1;

# disable tty cache line
$term = POSIX::Termios->new;
$term->getattr(fileno(STDIN));

echoOff;
gotoRaw if ($client);
*/

	if (pipe(inpipes) || pipe(outpipes))
		die("error creating pipes");

	switch(fork()) {
	case 0:
		/* replace files */
		dup2(inpipes[0], 0);
		dup2(outpipes[1], 1);

		p = malloc(strlen(server) + strlen(shellCmd) + 10);
		sprintf(p, "%s %s", shellCmd, server);
		execlp("sh", "sh", "-c", p, NULL);
		return 1;
		break;
	case -1:
		die("fork error");
	}
	close(inpipes[0]);
	close(outpipes[1]);
	READ = outpipes[0];
	WRITE = inpipes[1];

	signal(SIGPIPE, SIG_IGN);
	if (!client)
		signal(SIGINT, SIG_IGN);

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

		channelsSelect(max_fd, &fds_read, &fds_write, &fds_error);

		if (FD_ISSET(READ, &fds_error))
			die("READ");
		if (FD_ISSET(WRITE, &fds_error))
			die("WRITE");

		if (FD_ISSET(STDIN, &fds_read)) {
			char data[MAX_DATA_LEN+1];
			ssize_t res = read(STDIN, data, MAX_DATA_LEN);
			if (res <= 0)
				die("broken pipe %s", endPoint);
			data[res] = 0;
			if (!client)
				debug("\nfrom client='%s'", data);
			if (!client)
				res = process(data, res);
			mywrite(WRITE, data, res);
		}

		if (FD_ISSET(READ, &fds_read)) {
			char data[MAX_DATA_LEN+1];
			ssize_t res = read(READ, data, MAX_DATA_LEN);
			if (res <= 0)
				die("broken pipe %s", endPoint);
			data[res] = 0;
			debug("\norig='%s'", data);
			if (client)
				res = process(data, res);
			mywrite(STDOUT, data, res);
		}
	}

	return 1;
}
