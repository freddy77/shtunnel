# $Id: Makefile.am,v 1.5 2012-02-27 19:03:15 cvswrite Exp $
bin_PROGRAMS	= shtunnel classifier
TESTS		= test.sh

classifier_SOURCES = classifier.c config.h sshtty.c sshpty.c sshpty.h includes.h bsd-openpty.c cuse.c cuse.h
shtunnel_SOURCES = shtunnel.c config.h sshtty.c sshpty.c sshpty.h includes.h bsd-openpty.c
classifier_CFLAGS = @CLASSIFIER_CFLAGS@
classifier_LDADD  = @CLASSIFIER_LDADD@
