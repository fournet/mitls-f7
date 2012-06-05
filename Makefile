include Makefile.inc

name = OurTLS
version = 0.0.internal
distname = $(name)-$(version)

projs = ManagedRC4 lib TLSharp HttpServer RPCClient RPCServer doc
localfiles = Makefile.inc Makefile_default.inc

.PHONY = all dist dist-this build clean clean-dist

all: dist

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
 	
build:
	for i in $(projs) ; do\
		$(MAKE) -C $$i build ;\
	done

clean:
	for i in $(projs) ; do\
		$(MAKE) -C $$i clean ;\
	done

dist-clean: clean
	rm -rf $(distname).tar.gz $(distname)