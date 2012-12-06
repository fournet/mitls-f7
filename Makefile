# -*- Makefile -*-

# --------------------------------------------------------------------
name      = miTLS
version  ?= 0.0.internal
distname ?= $(name)-$(version)

subdirs  += 3rdparty CoreCrypto lib TLSharp
subdirs  += HttpServer echo rpc
subdirs  += www-data

sp13distname = $(name)-$(version)-sp13

.PHONY: all build make.in prepare-dist
.PHONY: do-dist-check dist dist-check sp13-check

all: build

build:
	[ -d bin ] || mkdir bin
	set -e; for d in $(subdirs); do $(MAKE) -f Makefile.build -C $$d; done

make.in:
	set -e; for d in $(subdirs); do $(MAKE) -f Makefile.build -C $$d make.in; done

prepare-dist:
	rm -rf $(distname) && mkdir $(distname)
	rm -rf $(distname).tgz
	set -e; for d in $(subdirs); do \
	   mkdir $(distname)/$$d; \
	   cp $$d/Makefile.build $(distname)/$$d; \
	   $(MAKE) -f Makefile.build -C $$d distdir=../$(distname)/$$d dist; \
	done
	cp -r licenses            $(distname)
	cp Makefile               $(distname)
	cp Makefile.config        $(distname)
	cp Makefile.config.cygwin $(distname)
	cp Makefile.config.unix   $(distname)
	cp README                 $(distname)
	find $(distname) -type f -exec chmod a-x '{}' \+

dist: prepare-dist
	tar --format=posix -czf $(distname).tgz $(distname)
	rm -rf $(distname)

do-dist-check:
	tar -xof $(distname).tgz
	cd $(distname) && $(MAKE) && $(MAKE) dist
	tar -C $(distname) -xof $(distname).tgz
	tar -C $(distname) -df $(distname).tgz $(distname)
	rm -rf $(distname)
	@echo "$(distname).tgz is ready for distribution"

dist-check: dist do-dist-check

sp13: anonymize LICENSE.sp13
	$(MAKE) distname=$(sp13distname) prepare-dist
	cp LICENSE.sp13 $(sp13distname)
	find $(sp13distname) \
	  -type f -regex '.*\.fs.?' \
	  -exec ./anonymize -B --header=LICENSE.sp13 '{}' \+
	tar --format=posix -czf $(sp13distname).tgz $(sp13distname)
	rm -rf $(sp13distname)

sp13-check: sp13
	$(MAKE) distname=$(sp13distname) do-dist-check

clean:
	rm -rf bin
	rm -f $(distname).tgz
