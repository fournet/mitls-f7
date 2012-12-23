# -*- Makefile -*-

# --------------------------------------------------------------------
.PHONY: all clean

CC       = gcc
CFLAGS  += -O2 -I/sw/lib/endian-dev -Wall -W -ggdb \
             $(shell pkg-config --cflags libevent) \
             $(shell pkg-config --cflags libevent_openssl) \
             $(shell log4c-config --cflags)
LDFLAGS +=
LIBS    += \
	$(shell pkg-config --libs libevent) \
	$(shell pkg-config --libs libevent_openssl) \
	$(shell log4c-config --libs)
LIBS    += -lssl

# --------------------------------------------------------------------
all: echo

echo: echo.c
	$(CC) -o $@ $(CFLAGS) $(LDFLAGS) $^ $(LIBS)

clean:
	rm -f echo
