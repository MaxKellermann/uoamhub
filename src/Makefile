# uoamhub Makefile
# (c) 2004 Max Kellermann <max@duempel.org>
# $Id: Makefile 95 2004-12-23 21:47:22Z max $

# auto-detect a C compiler
CC := $(shell for i in gcc-3.4 gcc-3.3 gcc cc; do which $$i && break; done )

# change the comments to enable the non-debugging version
CFLAGS = -g -O0
#CFLAGS = -Os -DNDEBUG=1

# uncomment this to enable the micro edition (16 kB binary size stripped)
#CFLAGS += -DDISABLE_DAEMON_CODE=1 -DDISABLE_LOGGING=1

WARNING_CFLAGS += -W -Wall -D_REENTRANT -std=gnu99 -Wmissing-prototypes -Wwrite-strings -Wcast-qual -Wfloat-equal -Wshadow -Wpointer-arith -Wbad-function-cast -Wsign-compare -Waggregate-return -Wmissing-declarations -Wmissing-noreturn -Wmissing-format-attribute -Wpacked -Wredundant-decls -Wnested-externs -Winline -Wdisabled-optimization -Wno-long-long -Wstrict-prototypes -Wundef -pedantic-errors -Werror

all: uoamhub

clean:
	rm -f uoamhub

uoamhub: uoamhub.c
	$(CC) $(CFLAGS) $(WARNING_CFLAGS) -o $@ $^

strip: uoamhub
	strip --strip-all uoamhub
