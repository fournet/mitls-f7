include ../Makefile.inc

localfiles = Makefile
src = TLStream.fs
deps = -r ../lib/TLSlib.dll -a
target = TLStream.dll

.PHONY: all build dist clean

all: build

$(target): $(src)
	$(target-fsc)
	
build: $(target)

clean: clean-def

dist: dist-def

include ../Makefile_default.inc