include Makefile.inc

name = OurTLS
version = 0.0.internal
distname = $(name)-$(version)

projs = ManagedRC4 lib TLSharp HttpServer RPCClient RPCServer www-data doc
localfiles = Makefile Makefile.inc Makefile_default.inc

.PHONY = all dist dist-this build clean clean-dist

all: build

dist-this:
	cp $(localfiles) $(distname)

dist:
	rm -rf $(distname)
	mkdir $(distname)
	for i in $(projs) ; do\
		$(MAKE) distname=../$(distname) this=$$i -C $$i dist ;\
	done
	$(MAKE) dist-this
	tar cfz $(distname).tar.gz $(distname)
	rm -rf $(distname)

dist-check: dist
	tar xfz $(distname).tar.gz
	$(MAKE) -C $(distname) build
	rm -rf $(distname)
 	
build:
	rm -rf bin
	mkdir bin
	for proj in $(projs) ; do\
		$(MAKE) -C $$proj build ;\
	done

clean:
	for i in $(projs) ; do\
		$(MAKE) -C $$i clean ;\
	done
	rm -rf bin

dist-clean: clean
	rm -rf $(distname).tar.gz $(distname)