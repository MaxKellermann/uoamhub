# uoamhub Makefile
# (c) 2004-2006 Max Kellermann <max@duempel.org>
# $Id: Makefile 140 2006-03-08 14:36:50Z make $

CC := gcc

# change this value to 'yes' to enable the debugging version
DEBUG = no

ifeq ($(DEBUG),yes)
CFLAGS += -g -O0
LDFLAGS = -g -O0
else
CFLAGS = -O3 -DNDEBUG=1
LDFLAGS = -O3
endif

# uncomment this to enable the micro edition (16 kB binary size stripped)
#FEATURE_CFLAGS += -DDISABLE_DAEMON_CODE=1 -DDISABLE_LOGGING=1

ifeq ($(DEBUG),yes)
WARNING_CFLAGS += -W -Wall -D_REENTRANT -std=gnu99 -Wmissing-prototypes -Wwrite-strings -Wcast-qual -Wfloat-equal -Wshadow -Wpointer-arith -Wbad-function-cast -Wsign-compare -Waggregate-return -Wmissing-declarations -Wmissing-noreturn -Wmissing-format-attribute -Wpacked -Wredundant-decls -Wnested-externs -Winline -Wdisabled-optimization -Wno-long-long -Wstrict-prototypes -Wundef -pedantic-errors -Werror
else
WARNING_CFLAGS += -std=gnu99
endif

ifeq ($(CC),)
$(error No C compiler detected; you could try "$(MAKE) CC=/usr/bin/my_c_compiler")
endif

ifeq ($(shell uname -s),SunOS)
LDFLAGS += -lsocket -lnsl
endif

ifeq ($(shell test -c /dev/urandom && echo yes),yes)
FEATURE_CFLAGS += -DHAVE_DEV_RANDOM -DRANDOM_DEVICE=\"/dev/urandom\"
else
ifeq ($(shell test -c /dev/random && echo yes),yes)
FEATURE_CFLAGS += -DHAVE_DEV_RANDOM -DRANDOM_DEVICE=\"/dev/random\"
endif
endif

SOURCES = src/uoamhub.c src/log.c \
	src/host.c src/domain.c src/client.c \
	src/config.c src/cmdline.c
OBJECTS = $(patsubst %.c,%.o,$(SOURCES))
HEADERS = $(wildcard src/*.h)

all: src/uoamhub

clean:
	rm -f src/uoamhub

$(OBJECTS): %.o: %.c $(HEADERS)
	$(CC) -c $< -o $@ $(CFLAGS) $(WARNING_CFLAGS) $(FEATURE_CFLAGS)

src/uoamhub: $(OBJECTS)
	$(CC) -o $@ $^ $(LDFLAGS)

strip: src/uoamhub
	strip --strip-all src/uoamhub
