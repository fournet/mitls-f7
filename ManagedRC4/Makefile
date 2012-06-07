include ../Makefile.inc

localfiles = Makefile 
src = 
deps = 
target = ManagedRC4.dll

.PHONY: all build dist clean

all: build

build:
	cp $(arch)/Release/$(target) ../bin

clean: clean-def

dist:
	mkdir $(distname)/$(this)
	tar --exclude=".svn" -c -f - * | (cd $(distname)/$(this); tar xfp -)

include ../Makefile_default.inc