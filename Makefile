include Makefile.inc

name = TLS
version = 0.0.internal

projs = HttpServer lib ManagedRC4 TLSharp RPCClient RCPServer doc
distdir = __dist
localfiles = Makefile.inc

.PHONY = all dist dist-this build clean

all: dist

dist-this:
	cp $(localfiles) $(distdir)

dist:
	rm -rf $(distdir)
	mkdir $(distdir)
	for i in $(projs) ; do\
		$(MAKE) distdir=../$(distdir) -C $$i dist ;\
	done
	$(MAKE) dist-this
	tar cfz 
 	
build:
	for i in $(projs) ; do\
		$(MAKE) -C $$i build ;\
	done

clean:
	for i in $(projs) ; do\
		$(MAKE) -C $$i clean ;\
	done