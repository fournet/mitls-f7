#! -*- Makefile -*-

# --------------------------------------------------------------------
.PHONY: all clean jsse

PKGC   = pkg-config
LOG4C  = log4c-config

CC      := gcc -ggdb
CFLAGS  := -I ../c-stub -Wall -W
CFLAGS  += $(shell $(PKGC) --cflags libssl) 
CFLAGS  += $(shell $(LOG4C) --cflags)
LDFLAGS :=
LIBS    := $(shell $(PKGC) --libs libssl) $(shell $(LOG4C) --libs)

ESRC    = echo-memory.c echo-ssl.c echo-log.c
OSRC    = $(patsubst %,../c-stub/%,$(ESRC)) openssl.c

# --------------------------------------------------------------------
all: openssl

openssl: $(OSRC)
	$(CC) -o $@ $(CFLAGS) $(LDFLAGS) $(OSRC) $(LIBS)

jsse:
	rm -rf jsse && mkdir jsse
	javac -d jsse JSSE.java

clean:
	rm -rf jsse openssl
