#! -*- Makefile -*-

# --------------------------------------------------------------------
.PHONY: all clean jsse jsse-server jsse-client

PKGC   = pkg-config
LOG4C  = log4c-config

CC      := gcc -ggdb -O2
CFLAGS  := -I ../c-stub -Wall -W
CFLAGS  += $(shell $(PKGC) --cflags libssl) 
CFLAGS  += $(shell $(LOG4C) --cflags)
LDFLAGS :=
LIBS    := $(shell $(PKGC) --libs libssl) $(shell $(LOG4C) --libs)

ESRC := echo-memory.c echo-ssl.c echo-log.c
ESRC := $(patsubst %,../c-stub/%,$(ESRC))

# --------------------------------------------------------------------
all: openssl openssl-server openssl-client jsse jsse-server jsse-client

openssl: openssl.c $(ESRC)
	$(CC) -o $@ $(CFLAGS) $(LDFLAGS) $^ $(LIBS)

openssl-server: openssl-server.c $(ESRC)
	$(CC) -o $@ $(CFLAGS) $(LDFLAGS) $^ $(LIBS)

openssl-client: openssl-client.c $(ESRC)
	$(CC) -o $@ $(CFLAGS) $(LDFLAGS) $^ $(LIBS)

jsse:
	rm -rf jsse && mkdir jsse
	javac -d jsse JSSE.java

jsse-server:
	rm -rf jsse-server && mkdir jsse-server
	javac -d jsse-server JSSEServer.java

jsse-client:
	rm -rf jsse-client && mkdir jsse-client
	javac -d jsse-client JSSEClient.java

clean:
	rm -rf jsse jsse-server jsse-client
	rm -rf openssl openssl-server openssl-client
