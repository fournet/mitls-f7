#! -*- Makefile -*-

# --------------------------------------------------------------------
.PHONY: all clean jsse jsse-server jsse-client

ifeq ($(TARGET), mingw)
EXE   = .exe
CROSS = i686-pc-mingw32-
else
EXE   =
CROSS =
endif

PKGC   = $(CROSS)pkg-config
LOG4C  = $(CROSS)log4c-config

CC      := $(CROSS)gcc
CFLAGS  := -I ../c-stub -Wall -W -Wno-unused-function
CFLAGS  += $(shell $(PKGC) --cflags libevent) 
CFLAGS  += $(shell $(PKGC) --cflags libssl) 
CFLAGS  += $(shell $(LOG4C) --cflags)
LDFLAGS :=
LIBS    := -lpthread \
  $(shell $(PKGC) --libs libevent) \
  $(shell $(PKGC) --libs libssl) \
  $(shell $(LOG4C) --libs)

ifeq ($(TARGET), mingw)
LIBS += -lws2_32 -lexpat
endif

ESRC := echo-memory.c echo-ssl.c echo-log.c
ESRC := $(patsubst %,../c-stub/%,$(ESRC))

# --------------------------------------------------------------------
all: openssl$(EXE) openssl-server$(EXE) openssl-client$(EXE) jsse jsse-server jsse-client

openssl$(EXE): openssl.c $(ESRC)
	$(CC) -o $@ $(CFLAGS) $(LDFLAGS) $^ $(LIBS)

openssl-server$(EXE): openssl-server.c $(ESRC)
	$(CC) -o $@ $(CFLAGS) $(LDFLAGS) $^ $(LIBS)

openssl-client$(EXE): openssl-client.c $(ESRC)
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
