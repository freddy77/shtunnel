#include "includes.h"
#include <assert.h>
#include "sshpty.h"

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

static int use_color = 0;

typedef struct {
	int read;
	int write;
	int num;
} pipe_t;

static int
handle_data(fd_set *fds_read, pipe_t *pipe, int *cur_pipe)
{
	char data[1024], *p, *pend;
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

	if (*cur_pipe != pipe->num && *cur_pipe != -1 && !use_color) {
		fprintf(stdout, "\n+");
		*cur_pipe = -1;
	}

	/* write all lines prefixed by handle */
	p = data;
	pend = p + res;
	for (;p != pend;) {
		char *next;
		char *nl = (char *) memchr(p, '\n', pend - p);
		if (!nl) {
			next = nl = pend;
		} else {
			next = nl + 1;
			if (nl > p && nl[-1] == '\r')
				--nl;
		}
		if (*cur_pipe != pipe->num) {
			if (use_color) {
				if (pipe->num == 2)
					fprintf(stdout, "\x1b[00;31m");
			} else {
				fprintf(stdout, "%d:", pipe->num);
			}
			*cur_pipe = pipe->num;
		}
		fwrite(p, 1, nl - p, stdout);
		if (nl == next)
			break;
		if (use_color && pipe->num == 2)
			fprintf(stdout, "\x1b[00m");
		fwrite(nl, 1, next - nl, stdout);
		*cur_pipe = -1;
		p = next;
	}
	return res;
}

static int
my_pipe(pipe_t *p, int num)
{
	int fd[2];
	int res;
	char ttyname[128];

	if (num <= 0)
		res = !pty_allocate(&fd[0], &fd[1], ttyname, sizeof(ttyname));
	else
		res = pipe(fd);
	p->read = fd[0];
	p->write = fd[1];
	p->num = num;
	return res;
}

int
main(int argc, char **argv)
{
#define MAX_STREAMS 8
	pipe_t pipes[MAX_STREAMS];
	int i, num_pipe = 2;
	int max_fd = 0;
	int ret;
	int cur_pipe = -1;
	int nice_res;
	pid_t pid;

	ret = 0;
	while (argc >= 2 && !ret) {
		if (strncmp(argv[1], "--num-fd=", 9) == 0) {
			num_pipe = atoi(argv[1] + 9);
			if (num_pipe < 2 || num_pipe > MAX_STREAMS)
				ret = 1;
			--argc;
			++argv;
		} else if (strcmp(argv[1], "--color") == 0) {
			use_color = 1;
			--argc;
			++argv;
		} else
			break;
	}

	if (ret || argc < 2)
		fatal("Syntax: classifier [--color] [--num-fd=xx] command [arg] ...\n"
			"\t--num-fd=xx\tNumber of stream to handle [2-%d]\n"
			"\t--color\tUse colors for output", MAX_STREAMS);

	
	for (i = 0; i < num_pipe; ++i) {
		if (my_pipe(&pipes[i], i + 1))
			fatal("allocating pipes");
	}

	/* try to increase our priority */	
	nice_res = nice(-2);

	/* execute sub process */
	switch (fork()) {
	case 0:
		for (i = 0; i < num_pipe; ++i) {
			/* close reading pipes */
			close(pipes[i].read);

			/* replacing out/err with our ones */
			if (dup2(pipes[i].write, pipes[i].num) < 0)
				fatal("dup2 pipe %d: %s", pipes[i].num, strerror(errno));
			close(pipes[i].write);
		}

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

	/* wait data from our child */
	for (;;) {
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

		for (i = 0; i < num_pipe; ++i)
			if (handle_data(&fds_read, &pipes[i], &cur_pipe) > 0)
				continue;
	}

	/* wait child exit */
	while ((pid = wait(&ret)) <= 0 && errno == EINTR);

	/* return corrent result */
	if (WIFEXITED(ret))
		return WEXITSTATUS(ret);
	if (WIFSIGNALED(ret))
		return 1;

	return 0;
}
