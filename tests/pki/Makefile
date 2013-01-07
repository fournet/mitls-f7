# -*- Makefile -*-

# --------------------------------------------------------------------
export PKI := $(CURDIR)

# --------------------------------------------------------------------
C  = CC
ST = State
L  = Location
O  = Organization
OU = 
CN = mitls.org
EA = root@mitls.org

CASUBJECT=/C=$(C)/ST=$(ST)/L=$(L)/O=$(O)/OU=$(OU)/CN=$(CN)/emailAddress=$(EA)

# --------------------------------------------------------------------
uname_S := $(shell sh -c 'uname -s 2>/dev/null || echo not')
uname_M := $(shell sh -c 'uname -m 2>/dev/null || echo not')
uname_O := $(shell sh -c 'uname -o 2>/dev/null || echo not')
uname_R := $(shell sh -c 'uname -r 2>/dev/null || echo not')
uname_P := $(shell sh -c 'uname -p 2>/dev/null || echo not')
uname_V := $(shell sh -c 'uname -v 2>/dev/null || echo not')

# --------------------------------------------------------------------
define layout
	if [ ! -d db ]; then                 \
		mkdir db;                    \
		mkdir db/ca.db.certs;        \
		touch db/ca.db.serial;       \
		touch db/ca.db.index;        \
		echo '01' > db/ca.db.serial; \
	fi

	if [ ! -d certificates ]; then \
		mkdir certificates;    \
	fi

	if [ ! -d imported ]; then \
		mkdir imported;    \
	fi
endef

# --------------------------------------------------------------------
.PHONY: ca dh layout clean hash

.PRECIOUS: %.p12
.PRECIOUS: %.key
.PRECIOUS: %.crt
.PRECIOUS: certificates/%.csr
.PRECIOUS: certificates/ca.key
.PRECIOUS: certificates/ca.crt

# --------------------------------------------------------------------
all:
	@echo "No default rule" >&2

# --------------------------------------------------------------------
ca: layout certificates/ca.crt

certificates/ca.crt: certificates/ca.key
	openssl req -new -x509 -batch          \
	    -subj   "$(CASUBJECT)"             \
	    -config config/ca.config           \
	    -key    certificates/ca.key \
	    -out    certificates/ca.crt
	openssl x509 -in certificates/ca.crt -noout -text

# --------------------------------------------------------------------
dh: layout certificates/dh.pem

certificates/dh.pem:
	openssl dhparam -out certificates/dh.pem 1024

# --------------------------------------------------------------------
%.p12: %.key %.crt certificates/ca.crt
	echo | openssl pkcs12 -export -password stdin \
	    -in       $*.crt   \
	    -inkey    $*.key   \
	    -name     "uTLS PKI ($*)" \
	    -out      $*.p12

#	    -certfile certificates/ca.crt \
#	    -caname   "uTLS PKI (CA)"     \

certificates/%.csr: certificates/%.key
	openssl req -new -batch \
	    -subj   "/C=$(C)/ST=$(ST)/L=$(L)/O=$(O)/OU=$(OU)/CN=$*/emailAddress=$(EA)" \
	    -config config/ca.config \
	    -key    $< \
	    -out    $@

%.crt: %.csr certificates/ca.crt
	openssl ca -batch -config config/ca.config -in $< -out $@
	openssl x509 -in $@ -noout -text

# --------------------------------------------------------------------
IMPORTED := $(wildcard imported/*.imported)
IMPORTED := $(patsubst imported/%.imported,%,$(IMPORTED))
IMPORTED := $(filter-out ca,$(IMPORTED))

ifeq ($(uname_O),Cygwin)
imported/ca.imported:
	certutil -f -user -addstore Root certificates/ca.crt
	touch $@

imported/%.imported: certificates/%.p12
	certutil -f -user -p '' -v -importpfx certificates/$*.p12
	touch $@

clean-store:
	certutil -user -delstore Root mitls.org
	for i in $(IMPORTED); do                   \
	  certutil -user -delstore My $$i || true; \
	done
	sleep 2						# Yes, I know...
else
imported/ca.imported:
	umask 077; certmgr -add -c Trust certificates/ca.crt
	touch $@

imported/%.imported: certificates/%.p12
	umask 077; ( set -e;                                 \
	  certmgr -add       -c My certificates/$*.crt;      \
	  certmgr -importKey -c -p '' My certificates/$*.p12 \
	)
	touch $@

clean-store:
	for i in $$(support/mono-crt-cleanup.py $(CN) $(IMPORTED)); do \
	  certmgr -del -c My    $$i || true; \
	  certmgr -del -c Trust $$i || true; \
	done
endif

# --------------------------------------------------------------------
%.key:
	openssl genrsa -out $@ 1024

# --------------------------------------------------------------------
hash:
	cd db/ca.db.certs && c_rehash .

# --------------------------------------------------------------------
layout:
	$(call layout)

# --------------------------------------------------------------------
clean: clean-store
	rm -rf certificates
	rm -rf db
	rm -rf imported
