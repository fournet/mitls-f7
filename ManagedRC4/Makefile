include ../Makefile.inc

localfiles = Makefile 
src = 
deps = 
target = ManagedRC4.dll

.PHONY: all build dist clean

all: dist

build:
	cp $(arch)/Release/$(target) ../bin

clean: clean-def

dist:
	mkdir $(distname)/$(this)
	cp -a . $(distname)/$(this)

include ../Makefile_default.inc