include ../Makefile.inc

localfiles = Makefile
src = RPCServer.fs
deps = -r ../lib/TLSlib.dll
target = RPCServer.exe

.PHONY: all build dist clean

all: build

$(target): $(src)
	$(target-fsc)
	
build: $(target)

clean: clean-def

dist: dist-def

include ../Makefile_default.inc