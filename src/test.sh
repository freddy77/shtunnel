#!/bin/sh

# $Id: test.sh,v 1.3 2007-05-25 12:44:05 freddy Exp $

# shtunnel --debug --shell ls xxx < /dev/null
#  should work and not stall
OUT=`./shtunnel --debug --shell ls shtunnel < /dev/null 2> /dev/null | if read -t 2 XXX; then
	echo -n $XXX | cat -ve
fi`
EXP='shtunnel'
if test "$OUT" != "$EXP"; then
	echo "$LINENO: Wrong result '$OUT' expected '$EXP'" >&2
	exit 1
fi

# test reset color inside line
OUT=`./classifier --color sh -c 'echo -n ciao >&2; echo pippo' | cat -ve`
EXP='^[[00;31mciao^[[00mpippo$'
if test "$OUT" != "$EXP"; then
	echo "$LINENO: Wrong result '$OUT' expected '$EXP'" >&2
	exit 1
fi

# test reset color at end of line
OUT=`./classifier --color sh -c 'echo -n ciao >&2' | cat -ve`
rm log.txt
EXP='^[[00;31mciao^[[00m'
if test "$OUT" != "$EXP"; then
	echo "$LINENO: Wrong result '$OUT' expected '$EXP'" >&2
	exit 1
fi

echo All tests passed!
exit 0

