include ../Makefile.inc

localfiles = Makefile
src = RPCClient.fs
deps = -r ../lib/TLSlib.dll
target = RPCClient.exe

.PHONY: all build dist clean

all: dist

$(target): $(src)
	$(target-fsc)
	
build: $(target)

clean: clean-def

dist: dist-def

include ../Makefile_default.inc