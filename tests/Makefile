# -*- Makefile -*-

# --------------------------------------------------------------------
.PHONY: all clean

# --------------------------------------------------------------------
all: pki.built
	true # ./test-suite.py

pki.built:
	$(MAKE) -C pki clean
	$(MAKE) -C pki ca imported/ca.imported
	$(MAKE) -C pki imported/cert-01.mitls.org.imported
	$(MAKE) -C pki imported/cert-02.mitls.org.imported
	$(MAKE) -C pki hash
	touch $@

# --------------------------------------------------------------------
clean:
	$(MAKE) -C pki clean
	rm -f pki.built
