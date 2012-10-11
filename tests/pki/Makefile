# -*- Makefile -*-

# --------------------------------------------------------------------
export PKI := ${PWD}

# --------------------------------------------------------------------
C  = fr
ST = Ile de France
L  = Paris
O  = INRIA-MSR Joint Lab
OU = Security Group
CN = needham.inria.fr
EA = root@needham.inria.fr

CASUBJECT=/C=$(C)/ST=$(ST)/L=$(L)/O=$(O)/OU=$(OU)/CN=$(CN)/emailAddress=$(EA)

# --------------------------------------------------------------------
define layout
	if [ ! -d $(PKI)/db ]; then             \
		mkdir $(PKI)/db;                    \
		mkdir $(PKI)/db/ca.db.certs;        \
		touch $(PKI)/db/ca.db.serial;       \
		touch $(PKI)/db/ca.db.index;        \
		echo '01' > $(PKI)/db/ca.db.serial; \
	fi

	if [ ! -d $(PKI)/certificates ]; then \
		mkdir $(PKI)/certificates;        \
	fi
endef

# --------------------------------------------------------------------
.PHONY: ca dh layout clean hash

.PRECIOUS: %.p12
.PRECIOUS: %.key
.PRECIOUS: %.crt
.PRECIOUS: certificates/cert-%.needham.inria.fr.csr
.PRECIOUS: certificates/ca.key
.PRECIOUS: certificates/ca.crt

# --------------------------------------------------------------------
all:
	@echo "No default rule" >&2

# --------------------------------------------------------------------
ca: layout certificates/ca.crt

certificates/ca.crt: certificates/ca.key
	openssl req -new -x509 -batch   \
	    -subj   "$(CASUBJECT)"      \
	    -config config/ca.config    \
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
	    -in       $*.crt              \
	    -inkey    $*.key              \
	    -name     "uTLS PKI ($*)"     \
	    -certfile certificates/ca.crt \
	    -caname   "uTLS PKI (CA)"     \
	    -out      $*.p12

certificates/cert-%.needham.inria.fr.csr: certificates/cert-%.needham.inria.fr.key
	openssl req -new -batch \
	    -subj   "/C=$(C)/ST=$(ST)/L=$(L)/O=$(O)/OU=$(OU)/CN=cert-$*.$(CN)/emailAddress=$(EA)" \
	    -config config/ca.config \
	    -key    $< \
	    -out    $@

%.crt: %.csr certificates/ca.crt
	openssl ca -batch -config config/ca.config -in $< -out $@
	openssl x509 -in $@ -noout -text

# --------------------------------------------------------------------
%.key:
	openssl genrsa -out $@ 1024

# --------------------------------------------------------------------
hash:
	cd $(PKI)/db/ca.db.certs && c_rehash

# --------------------------------------------------------------------
layout:
	$(call layout)

# --------------------------------------------------------------------
clean:
	rm -rf $(PKI)/certificates
	rm -rf $(PKI)/db
