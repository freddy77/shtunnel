/* classifier - program to color command streams
 * Copyright (C) 2004-2008  Frediano Ziglio
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
#include "cuse.h"

static volatile int got_alarm = 0;
static pid_t child_pid = 0;

void fatal(const char *msg, ...)
{
	va_list ap;

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

typedef enum {
	OutType_Normal,
	OutType_Color,
	OutType_Html
} OutType;

static OutType out_type = OutType_Normal;
static int out_html_full = 0;

typedef struct {
	int read;
	int write;
	int num;
} pipe_t;

static int cur_pipe = -1;

void
handle_buf(const char *buf, size_t len, int pipe_num)
{
	const char *p, *pend;

	if (cur_pipe != pipe_num && cur_pipe != -1) {
		if (out_type == OutType_Normal)
			fprintf(stdout, "\n+");
		else if (out_type == OutType_Color && cur_pipe >= 2)
			fprintf(stdout, "\x1b[00m");
		else if (out_type == OutType_Html && cur_pipe >= 2)
			fprintf(stdout, "</span>");
		cur_pipe = -1;
	}

	/* write all lines prefixed by handle */
	p = buf;
		pend = p + len;
		for (;p != pend;) {
			/*
			 * in a string like
			 * "pippo" "\n" "pluto...
			 * p       nl   next
			 */
			const char *next;
			const char *nl = (char *) memchr(p, '\n', pend - p);
			if (!nl) {
				next = nl = pend;
			} else {
				next = nl + 1;
				if (nl > p && nl[-1] == '\r')
					--nl;
			}

			/* start line */
			if (cur_pipe != pipe_num) {
			switch (out_type) {
			case OutType_Color:
				if (pipe_num >= 2)
					fprintf(stdout, "\x1b[00;3%dm", ((pipe_num - 2) % 7) + 1);
				break;
			case OutType_Normal:
				fprintf(stdout, "%d:", pipe_num);
				break;
			case OutType_Html:
				if (pipe_num == 2)
					fprintf(stdout, "<span class=\"error\">");
				else if (pipe_num > 1)
					fprintf(stdout, "<span class=\"stream%d\">", pipe_num);
				break;
			}
			cur_pipe = pipe_num;
		}

		/* line */
		if (out_type == OutType_Html) {
			for (; p != nl; ++p)
				switch (*p) {
				case '<':
					fprintf(stdout, "&lt;");
					break;
				case '>':
					fprintf(stdout, "&gt;");
					break;
				case '"':
					fprintf(stdout, "&quot;");
					break;
				case '&':
					fprintf(stdout, "&amp;");
					break;
				default:
					putc(*p, stdout);
					break;
				}
		} else {
			fwrite(p, 1, nl - p, stdout);
		}
		if (nl == next)
			break;

		/* end line */
		switch (out_type) {
		case OutType_Color:
			if (pipe_num >= 2)
				fprintf(stdout, "\x1b[00m");
		case OutType_Normal:
			break;
		case OutType_Html:
			if (pipe_num > 1)
				fprintf(stdout, "</span>");
			break;
		}
		fwrite(nl, 1, next - nl, stdout);
		cur_pipe = -1;

		p = next;
	}
}

static int
handle_data(fd_set *fds_read, pipe_t *pipe, int *cur_pipe)
{
	char data[1024];
	ssize_t res;

	if (pipe->read < 0 || !FD_ISSET(pipe->read, fds_read))
		return 0;
	res = read(pipe->read, data, sizeof(data));

	/* broken pipe assume child exited */
	if (res <= 0) {
		close(pipe->read);
		pipe->read = -1;
		return res;
	}

	handle_buf(data, res, pipe->num);
	return res;
}

static int
my_pipe(pipe_t *p, int num)
{
	int fd[2];
	int res;

	if (cuse_allocate(num, &fd[1])) {
		fd[0] = -1;
		res = 0;
	} else if (num <= 2) {
		char ttyname[128];
		res = !pty_allocate(&fd[0], &fd[1], ttyname, sizeof(ttyname));
		if (!res) set_raw_mode(fd[1], NULL);
	} else {
		res = pipe(fd);
	}
	if (!res)
		fcntl(fd[1], F_SETFL, fcntl(fd[1],F_GETFL) | O_SYNC);
	p->read = fd[0];
	p->write = fd[1];
	p->num = num;
	return res;
}

static void
kill_child(int sig_num)
{
	got_alarm = 1;
	alarm(0);
	if (child_pid)
		kill(child_pid, SIGKILL);
	child_pid = 0;
}

int
main(int argc, char **argv)
{
#define MAX_STREAMS 8
	pipe_t pipes[MAX_STREAMS];
	int i, num_pipe = 2;
	int max_fd = 0;
	int ret;
	int nice_res;
	int timeout = -1;
	pid_t pid;
	unsigned int byte_count = 0;
	unsigned int byte_limit = 0;

	ret = 0;
	while (argc >= 2 && !ret) {
		if (strncmp(argv[1], "--num-fd=", 9) == 0) {
			num_pipe = atoi(argv[1] + 9);
			if (num_pipe < 2 || num_pipe > MAX_STREAMS)
				ret = 1;
		} else if (strncmp(argv[1], "--timeout=", 10) == 0) {
			timeout = atoi(argv[1] + 10);
			if (timeout <= 0)
				ret = 1;
		} else if (strncmp(argv[1], "--byte-limit=", 13) == 0) {
			int i = atoi(argv[1] + 13);
			if (i <= 0)
				ret = 1;
			byte_limit = i;
		} else if (strcmp(argv[1], "--color") == 0) {
			out_type = OutType_Color;
		} else if (strcmp(argv[1], "--html") == 0) {
			out_type = OutType_Html;
		} else if (strcmp(argv[1], "--html-full") == 0) {
			out_type = OutType_Html;
			out_html_full = 1;
		} else if (strcmp(argv[1], "--no-buffering") == 0) {
			setbuf(stdout, NULL);
		} else if (strcmp(argv[1], "--") == 0) {
			/* stop parsing argument */
			--argc;
			++argv;
			break;
		} else
			break;

		--argc;
		++argv;
	}

	if (ret || argc < 2)
		fatal("Syntax: classifier [OPTION]... command [arg] ...\n"
			"  --num-fd=xx     Number of stream to handle [2-%d]\n"
			"  --color         Use colors for output\n"
			"  --html          Use HTML for output\n"
			"  --html-full     Use default header/footer in HTML output\n"
			"  --no-buffering  Do not buffer output\n"
			"  --timeout=xx    Timeout in seconds\n"
			"  --byte-limit=xx Limit data to xx bytes", MAX_STREAMS);

	cuse_init();
	for (i = 0; i < num_pipe; ++i) {
		if (my_pipe(&pipes[i], i + 1))
			fatal("allocating pipes");
	}

	/* try to increase our priority */	
	nice_res = nice(-2);

#ifdef HAVE_GETRESUID
	uid_t uid = getuid();
	setresuid(uid, uid, uid);
	gid_t gid = getgid();
	setresgid(gid, gid, gid);
#endif

	/* execute sub process */
	child_pid = fork();
	switch (child_pid) {
	case 0:
		for (i = 0; i < num_pipe; ++i) {
			/* close reading pipes */
			close(pipes[i].read);

			/* replacing out/err with our ones */
			if (dup2(pipes[i].write, pipes[i].num) < 0)
				fatal("dup2 pipe %d: %s", pipes[i].num, strerror(errno));
			close(pipes[i].write);
		}
		/* close other eventual handles (like CUSE) */
		for (i = 0; i < 4; ++i)
			close(num_pipe + 1 + i);

		--argc;
		memmove(argv, argv + 1, sizeof(char*) * argc);
		argv[argc] = NULL;
		/* if main process cannot increase priority decrease child one */	
		if (nice_res)
			nice(2);
		execvp(argv[0], argv);
		fatal("exec fails");
		break;
	case -1:
		fatal("Error forking");
	}

	/* close unused write pipes, only read */
	max_fd = -1;
	for (i = 0; i < num_pipe; ++i) {
		close(pipes[i].write);
		pipes[i].write = -1;
		if (pipes[i].read > max_fd)
			max_fd = pipes[i].read;
	}

	/* ignore closing pipe */
	signal(SIGPIPE, SIG_IGN);
	signal(SIGTTOU, SIG_IGN);

	/* let child process handle Ctrl-C */
	signal(SIGINT, SIG_IGN);

	/* set alarm for timeout */
	if (timeout > 0) {
		signal(SIGALRM, kill_child);
		alarm(timeout);
	}

	if (out_type == OutType_Html && out_html_full) {
		int i;
		const char colors[7][8] = {
			"red",
			"green",
			"yellow",
			"blue",
			"cyan",
			"magenta",
			"gray"
		};

		fprintf(stdout, "<html>\n"
			"<style>\n"
			".error { color: red }\n");
		for (i = 1; i < 7 && (i + 2) <= num_pipe; ++i)
			fprintf(stdout, ".stream%d { color: %s }\n", i+2, colors[i]);
		fprintf(stdout, "</style>\n<body>\n<pre>");
	}

	/* wait data from our child */
	for (;!got_alarm;) {
		fd_set fds_read;
		int res;

		FD_ZERO(&fds_read);
		res = 1;
		for (i = 0; i < num_pipe; ++i)
			if (pipes[i].read >= 0) {
				FD_SET(pipes[i].read, &fds_read);
				res = 0;
			}
		if (res)
			break;

		res = select(max_fd + 1, &fds_read, NULL, NULL, NULL);
		if (res < 0) {
			if (errno != EINTR)
				fatal("select error %s", strerror(errno));
			continue;
		}

		for (i = 0; i < num_pipe; ++i) {
			int res = handle_data(&fds_read, &pipes[i], &cur_pipe);
			if (res > 0) {
				byte_count += res;
				if (byte_limit && byte_count > byte_limit)
					kill(child_pid, SIGKILL);
				continue;
			}
		}
	}

	/* wait child exit */
	while ((pid = wait(&ret)) <= 0 && errno == EINTR);

	if (out_type == OutType_Html && out_html_full)
		fprintf(stdout, "</pre>\n</body>\n</html>\n");

	if (out_type == OutType_Color && cur_pipe >= 2)
		fprintf(stdout, "\x1b[00m");

	/* return corrent result */
	if (WIFEXITED(ret))
		return WEXITSTATUS(ret);
	if (WIFSIGNALED(ret))
		return WTERMSIG(ret) + 128;

	return 0;
}
