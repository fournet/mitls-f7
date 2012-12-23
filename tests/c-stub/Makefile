# -*- Makefile -*-

# --------------------------------------------------------------------
.PHONY: all clean

CC       = gcc
CFLAGS  += -O2 -I/sw/lib/endian-dev -Wall -W -ggdb \
             $(shell pkg-config --cflags libevent) \
             $(shell log4c-config --cflags)
LDFLAGS +=
LIBS    += $(shell pkg-config --libs libevent) $(shell log4c-config --libs)
LIBS    += -lssl

# --------------------------------------------------------------------
all: echo

echo: echo.c
	$(CC) -o $@ $(CFLAGS) $(LDFLAGS) $^ $(LIBS)

clean:
	rm -f echo
