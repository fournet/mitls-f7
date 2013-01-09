# -*- Makefile -*-

# --------------------------------------------------------------------
.PHONY: all clean

# --------------------------------------------------------------------
uname_S := $(shell sh -c 'uname -s 2>/dev/null || echo not')
uname_M := $(shell sh -c 'uname -m 2>/dev/null || echo not')
uname_O := $(shell sh -c 'uname -o 2>/dev/null || echo not')
uname_R := $(shell sh -c 'uname -r 2>/dev/null || echo not')
uname_P := $(shell sh -c 'uname -p 2>/dev/null || echo not')
uname_V := $(shell sh -c 'uname -v 2>/dev/null || echo not')

# --------------------------------------------------------------------
all: pki.built
	if [ "$(uname_O)" != "Cygwin" ]; then \
	  $(MAKE) -C c-stub; \
	fi
	./test-suite.py

pki.built:
	$(MAKE) -C pki clean
	$(MAKE) -C pki dh
	$(MAKE) -C pki ca imported/ca.imported
	$(MAKE) -C pki imported/cert-01.mitls.org.imported
	$(MAKE) -C pki imported/cert-02.mitls.org.imported
	$(MAKE) -C pki hash
	touch $@

# --------------------------------------------------------------------
clean:
	$(MAKE) -C pki clean
	if [ "$(uname_O)" != "Cygwin" ]; then \
	  $(MAKE) -C c-stub clean; \
	fi
	rm -f pki.built
