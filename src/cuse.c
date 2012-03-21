#include "includes.h"
#if HAVE_CUSE

#include "cuse.h"

#define FUSE_USE_VERSION 28
//#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <errno.h>
#include <cuse_lowlevel.h>
#include <pthread.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <termios.h>

#define NCCS_KRNL 19
struct termios_krnl {
        tcflag_t c_iflag;               /* input mode flags */
        tcflag_t c_oflag;               /* output mode flags */
        tcflag_t c_cflag;               /* control mode flags */
        tcflag_t c_lflag;               /* local mode flags */
        cc_t c_line;                    /* line discipline */
        cc_t c_cc[NCCS_KRNL];           /* control characters */
};

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

static int ioctl_prep_uarg(fuse_req_t req, void *in, size_t in_sz, void *out,
			   size_t out_sz, void *uarg, const void *in_buf,
			   size_t in_bufsz, size_t out_bufsz)
{
	struct iovec in_iov = { }, out_iov = { };
	int retry = 0;

	if (in) {
		if (!in_bufsz) {
			in_iov.iov_base = uarg;
			in_iov.iov_len = in_sz;
			retry = 1;
		} else {
			assert(in_bufsz == in_sz);
			memcpy(in, in_buf, in_sz);
		}
	}

	if (out) {
		if (!out_bufsz) {
			out_iov.iov_base = uarg;
			out_iov.iov_len = out_sz;
			retry = 1;
		} else
			assert(out_bufsz == out_sz);
	}

	if (retry)
		fuse_reply_ioctl_retry(req, &in_iov, 1, &out_iov, 1);

	return retry;
}

#define PREP_UARG(inp, outp) do {					\
	if (ioctl_prep_uarg(req, (inp), sizeof(*(inp)),			\
			    (outp), sizeof(*(outp)), uarg,		\
			    in_buf, in_bufsz, out_bufsz))		\
		return;							\
} while (0)

#define IOCTL_RETURN(result, outp) do {					\
	if ((outp) != NULL)						\
		fuse_reply_ioctl(req, result, (outp), sizeof(*(outp)));	\
	else								\
		fuse_reply_ioctl(req, result, NULL, 0);			\
	return;								\
} while (0)

static pthread_cond_t initialized = PTHREAD_COND_INITIALIZER;

static void my_init_done(void *userdata)
{
	pthread_cond_signal(&initialized);
}

static int fd_id;

static void my_open(fuse_req_t req, struct fuse_file_info *fi)
{
	fi->direct_io = 1;
	fi->nonseekable = 1;
	fi->fh = fd_id;

	fuse_reply_open(req, fi);
//	fuse_reply_err(req, EINVAL);
}

static void my_release(fuse_req_t req, struct fuse_file_info *fi)
{
	fuse_reply_err(req, 0);
}

static void my_read(fuse_req_t req, size_t size, off_t off,
		     struct fuse_file_info *fi)
{
	printf("%s\n", __func__);
	fflush(stdout);
	fuse_reply_err(req, EINVAL);
}

void handle_buf(const char *buf, size_t len, int pipe_num);

static void my_write(fuse_req_t req, const char *buf, size_t size, off_t off,
		      struct fuse_file_info *fi)
{
	ssize_t ret = size;

	pthread_mutex_lock(&mutex);

	handle_buf(buf, size, fi->fh);

	pthread_mutex_unlock(&mutex);
	if (ret < 0)
		fuse_reply_err(req, errno);
	else
		fuse_reply_write(req, ret);
}

static void my_poll(fuse_req_t req, struct fuse_file_info *fi,
		     struct fuse_pollhandle *ph)
{
	printf("%s\n", __func__);
	fflush(stdout);
	fuse_reply_err(req, EINVAL);
}

static void my_ioctl(fuse_req_t req, int signed_cmd, void *uarg,
		      struct fuse_file_info *fi, unsigned int flags,
		      const void *in_buf, size_t in_bufsz, size_t out_bufsz)
{
	switch (signed_cmd) {
	case TCGETS: {
		struct termios_krnl ios_krnl;
		struct termios ios;

		PREP_UARG(NULL, &ios_krnl);
		if (ioctl(1, signed_cmd, &ios) < 0) {
			fuse_reply_err(req, errno);
			return;
		}
		memcpy(&ios_krnl, &ios, sizeof(ios_krnl));
		IOCTL_RETURN(0, &ios_krnl);
	}

	case TCSETS:
	case TCSETSF:
	case TCSETSW: {
		struct termios_krnl ios_krnl;
		struct termios ios;

		PREP_UARG(&ios_krnl, NULL);
		memset(&ios, 0, sizeof(ios));
		memcpy(&ios, &ios_krnl, sizeof(ios_krnl));
		if (ioctl(1, signed_cmd, &ios) < 0) {
			fuse_reply_err(req, errno);
			return;
		}
		IOCTL_RETURN(0, NULL);
	}

	case TIOCGWINSZ: {
		struct winsize ws;

		PREP_UARG(&ws, &ws);
		if (ioctl(1, signed_cmd, &ws) < 0) {
			fuse_reply_err(req, errno);
			return;
		}
		IOCTL_RETURN(0, &ws);
	}

	case TIOCGPGRP: {
		pid_t pid;

		PREP_UARG(NULL, &pid);
		if (ioctl(1, signed_cmd, &pid) < 0) {
			fuse_reply_err(req, errno);
			return;
		}
		IOCTL_RETURN(0, &pid);
	}

	case TIOCSPGRP: {
		pid_t pid;

		PREP_UARG(&pid, NULL);
		if (ioctl(1, signed_cmd, &pid) < 0) {
			fuse_reply_err(req, errno);
			return;
		}
		IOCTL_RETURN(0, NULL);
	}

	case TCXONC:
		if (ioctl(1, signed_cmd, (int) uarg) < 0) {
			fuse_reply_err(req, errno);
			return;
		}
		IOCTL_RETURN(0, NULL);

	default:
		printf("%s %x\n", __func__, signed_cmd);
		fflush(stdout);
		break;
	}
	fuse_reply_err(req, EINVAL);
}

static const struct cuse_lowlevel_ops my_ops = {
	.init_done		= my_init_done,
	.open			= my_open,
	.release		= my_release,
	.read			= my_read,
	.write			= my_write,
	.poll			= my_poll,
	.ioctl			= my_ioctl,
};

static void *cuse_worker(void *arg)
{
	struct fuse_session *se = arg;
	int rc;

	rc = fuse_session_loop_mt(se);
	cuse_lowlevel_teardown(se);

	return (void *)(unsigned long)rc;
}

static char devname[64];

void cuse_init(void)
{
	struct fuse_session *se;
	char name_buf[128];
	const char *bufp = name_buf;
	struct cuse_info ci = { .dev_major = 0, .dev_minor = 0,
				.dev_info_argc = 1, .dev_info_argv = &bufp,
				.flags = CUSE_UNRESTRICTED_IOCTL };
	pthread_t cuse_my_thread;
	char *my_argv[] = { "classifier", "-f", "-s" };
	int my_argc = sizeof(my_argv)/sizeof(my_argv[0]);

	sprintf(devname, "/dev/classifier%d", (int) getpid());
	snprintf(name_buf, sizeof(name_buf), "DEVNAME=%s", devname+5);

	int tmp_err = dup(2);
	int null = open("/dev/null", O_WRONLY);
	if (tmp_err >= 0 && null >= 0)
		dup2(null, 2);
	se = cuse_lowlevel_setup(my_argc, my_argv, &ci, &my_ops, NULL, NULL);
	if (tmp_err >= 0)
		dup2(tmp_err, 2);
	close(null);
	close(tmp_err);
	if (!se)
		return;

	pthread_mutex_lock(&mutex);
	pthread_create(&cuse_my_thread, NULL, cuse_worker, se);
	pthread_cond_wait(&initialized, &mutex);
	pthread_mutex_unlock(&mutex);
}

int cuse_allocate(int num, int *out_fd)
{
	fd_id = num;
	int fd_out = open(devname, O_RDWR);
	if (fd_out < 0)
		return 0;

	*out_fd = fd_out;
	return 1;
}

#endif
