include Makefile.inc

projs = HttpServer lib ManagedRC4 TLSharp RPCClient RCPServer doc

.PHONY = all dist build clean

all: dist

dist-this:

dist:
	rm -rf __dist
	mkdir __dist
	for i in $(projs) ; do\
		$(MAKE) top_distdir=$(dirname  -C $$i dist ;\
	done
 	
build:
	for i in $(projs) ; do\
		$(MAKE) -C $$i build ;\
	done

clean:
	for i in $(projs) ; do\
		$(MAKE) -C $$i clean ;\
	done