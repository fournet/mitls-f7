# -*- Makefile -*-

# --------------------------------------------------------------------
.PHONY: all clean

# --------------------------------------------------------------------
TARGET ?= unix					# allowed: unix, mingw

# --------------------------------------------------------------------
ifeq ($(TARGET), mingw)
EXE   = .exe
CROSS = i686-pc-mingw32-
else
EXE   =
CROSS =
endif

CC     = $(CROSS)gcc
LD     = $(CROSS)ld
AR     = $(CROSS)ar
PKGC   = $(CROSS)pkg-config
LOG4C  = $(CROSS)log4c-config

CFLAGS  += -O2 -I/sw/lib/endian-dev -Wall -W -Wno-unused-function \
             $(shell $(PKGC)  --cflags libevent) \
             $(shell $(PKGC)  --cflags libevent_openssl) \
             $(shell $(PKGC)  --cflags libssl) \
             $(shell $(LOG4C) --cflags)
LDFLAGS +=
LIBS    += \
	$(shell $(PKGC)  --libs libevent) \
	$(shell $(PKGC)  --libs libevent_openssl) \
    $(shell $(PKGC)  --libs libssl) \
	$(shell $(LOG4C) --libs)

ifeq ($(TARGET), mingw)
LIBS += -lws2_32 -lexpat
endif

# --------------------------------------------------------------------
all: echo$(EXE)

echo$(EXE): echo.c
	$(CC) -o $@ $(CFLAGS) $(LDFLAGS) $^ $(LIBS)

clean:
	rm -f echo
