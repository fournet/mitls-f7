# -*- Makefile -*-
# Automatically generated by: ./genrules -I ../Platform/Platform.fsproj -I ../CoreCrypto/CoreCrypto.fsproj -I ../lib/lib.fsproj pwapp.fsproj
# Generated on Mon Jun 23 17:43:38 2014
# Use [make regen] to regenerate this Makefile

include ../Makefile.config

lib7      = ../../../lib/fs7-interfaces/
libperv   = $(lib7)pervasives.fs7 $(lib7)tuples.fs7
lperv     = -pervasives $(lib7)pervasives.fs7 -tuples $(lib7)tuples.fs7
libfs7    = $(lib7)pi.fs7 $(lib7)formulas.fs7
f7timeout = 5
f7defs    = avoid verify ideal

# removed --verbose for automated testing
override f7flags += \
  -timeout $(f7timeout) $(patsubst %,--define %,$(f7defs)) \
  -nokindcheck $(lperv) $(libfs7)

.PHONY: default clean check-xunit regen

-include Makefile.tc7

# default verification targets 
default: PwToken.tc7 PwApp.tc7

clean:
	rm -f *.smp *.tc7 *.why

regen:
	./genrules \
	  -I ../Platform/Platform.fsproj \
	  -I ../CoreCrypto/CoreCrypto.fsproj \
	  -I ../lib/lib.fsproj \
	    pwapp.fsproj > Makefile.pwapp.$$ \
	|| { rm -f Makefile.pwapp.$$; false; }
	mv Makefile.pwapp.$$ Makefile

# ----- BEGIN AUTO FS7 -----
PwToken.tc7: $(libperv) $(libfs7) ../Platform/Error.fs7 ../Platform/Date.fs7 ../Platform/Bytes.fs7 ../CoreCrypto/CoreKeys.fsi ../CoreCrypto/CoreACiphers.fsi ../CoreCrypto/CoreSig.fsi ../CoreCrypto/DER.fsi ../lib/TLSError.fs7 ../lib/Nonce.fs7 ../lib/TLSConstants.fs7 ../lib/RSAKey.fs7 ../lib/DHGroup.fs7 ../lib/PMS.fs7 ../lib/Sig.fs7 ../lib/UntrustedCert.fs7 ../lib/Cert.fs7 ../lib/TLSInfo.fs7 ../lib/TLSExtensions.fs7 ../lib/Range.fs7 ../lib/DataStream.fs7 PwToken.fs7 PwToken.fs PwToken.fs7
	@echo 
	@echo Lemma $@
	$(monoexe) $(f7) $(f7flags) -scripts PwToken -why PwToken.why ../Platform/Error.fs7 ../Platform/Date.fs7 ../Platform/Bytes.fs7 ../CoreCrypto/CoreKeys.fsi ../CoreCrypto/CoreACiphers.fsi ../CoreCrypto/CoreSig.fsi ../CoreCrypto/DER.fsi ../lib/TLSError.fs7 ../lib/Nonce.fs7 ../lib/TLSConstants.fs7 ../lib/RSAKey.fs7 ../lib/DHGroup.fs7 ../lib/PMS.fs7 ../lib/Sig.fs7 ../lib/UntrustedCert.fs7 ../lib/Cert.fs7 ../lib/TLSInfo.fs7 ../lib/TLSExtensions.fs7 ../lib/Range.fs7 ../lib/DataStream.fs7 PwToken.fs7 PwToken.fs | tee $@

PwApp.tc7: $(libperv) $(libfs7) ../Platform/Error.fs7 ../Platform/Date.fs7 ../Platform/Bytes.fs7 ../Platform/Tcp.fs7 ../CoreCrypto/CoreKeys.fsi ../CoreCrypto/CoreCiphers.fsi ../CoreCrypto/CoreACiphers.fsi ../CoreCrypto/CoreSig.fsi ../CoreCrypto/DER.fsi ../lib/TLSError.fs7 ../lib/Nonce.fs7 ../lib/TLSConstants.fs7 ../lib/RSAKey.fs7 ../lib/DHGroup.fs7 ../lib/PMS.fs7 ../lib/Sig.fs7 ../lib/UntrustedCert.fs7 ../lib/Cert.fs7 ../lib/TLSInfo.fs7 ../lib/TLSExtensions.fs7 ../lib/Range.fs7 ../lib/DataStream.fs7 ../lib/AppFragment.fs7 ../lib/HSFragment.fs7 ../lib/TLSFragment.fs7 ../lib/StatefulPlain.fs7 ../lib/LHAEPlain.fs7 ../lib/MAC_SHA256.fs7 ../lib/MAC_SHA1.fs7 ../lib/MAC.fs7 ../lib/Encode.fs7 ../lib/ENC.fs7 ../lib/AEAD_GCM.fs7 ../lib/LHAE.fs7 ../lib/StatefulLHAE.fs7 ../lib/Record.fs7 ../lib/Alert.fs7 ../lib/PRF.fs7 ../lib/DH.fs7 ../lib/SessionDB.fs7 ../lib/HandshakeMessages.fs7 ../lib/Handshake.fs7 ../lib/AppData.fs7 ../lib/Dispatch.fs7 ../lib/TLS.fs7 PwToken.fs7 PwApp.fs7 PwApp.fs PwApp.fs7
	@echo 
	@echo Lemma $@
	$(monoexe) $(f7) $(f7flags) -scripts PwApp -why PwApp.why ../Platform/Error.fs7 ../Platform/Date.fs7 ../Platform/Bytes.fs7 ../Platform/Tcp.fs7 ../CoreCrypto/CoreKeys.fsi ../CoreCrypto/CoreCiphers.fsi ../CoreCrypto/CoreACiphers.fsi ../CoreCrypto/CoreSig.fsi ../CoreCrypto/DER.fsi ../lib/TLSError.fs7 ../lib/Nonce.fs7 ../lib/TLSConstants.fs7 ../lib/RSAKey.fs7 ../lib/DHGroup.fs7 ../lib/PMS.fs7 ../lib/Sig.fs7 ../lib/UntrustedCert.fs7 ../lib/Cert.fs7 ../lib/TLSInfo.fs7 ../lib/TLSExtensions.fs7 ../lib/Range.fs7 ../lib/DataStream.fs7 ../lib/AppFragment.fs7 ../lib/HSFragment.fs7 ../lib/TLSFragment.fs7 ../lib/StatefulPlain.fs7 ../lib/LHAEPlain.fs7 ../lib/MAC_SHA256.fs7 ../lib/MAC_SHA1.fs7 ../lib/MAC.fs7 ../lib/Encode.fs7 ../lib/ENC.fs7 ../lib/AEAD_GCM.fs7 ../lib/LHAE.fs7 ../lib/StatefulLHAE.fs7 ../lib/Record.fs7 ../lib/Alert.fs7 ../lib/PRF.fs7 ../lib/DH.fs7 ../lib/SessionDB.fs7 ../lib/HandshakeMessages.fs7 ../lib/Handshake.fs7 ../lib/AppData.fs7 ../lib/Dispatch.fs7 ../lib/TLS.fs7 PwToken.fs7 PwApp.fs7 PwApp.fs | tee $@

check-xunit: clean
	../scripts/xunit-tc7 --xunit=$(xunit) PwToken PwApp
# ----- END AUTO FS7 -----
