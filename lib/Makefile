include ../../../../Makefile.inc

#all: record.dll record-a.dll Dispatch.dll Dispatch-a.dll
all: record.dll Dispatch.dll TLS.dll

lib7=../../../lib/fs7-interfaces/
libperv = $(lib7)pervasives.fs7 $(lib7)tuples.fs7
lperv = -pervasives $(lib7)pervasives.fs7 -tuples $(lib7)tuples.fs7
libfs7 = $(lib7)formulas.fs7 $(lib7)pi.fs7

recordfs7 = Bytes.fs7 Error.fs7 tcp.fs7 RSA.fs7 Principal.fs7 Algorithms.fs7 CipherSuites.fs7 formats.fs7 TLSInfo.fs7 HASH.fs7 HMAC.fs7 MAC.fs7 TLSPlain.fs7 ENC.fs7 AEAD.fs7 Stream.fs7 record.fs7
recordfsi = Bytes.fsi Error.fsi tcp.fsi RSA.fsi Principal.fsi Algorithms.fsi CipherSuites.fsi formats.fsi TLSInfo.fsi HASH.fsi HMAC.fsi MAC.fsi TLSPlain.fsi ENC.fsi AEAD.fsi Stream.fsi record.fsi
recordfs = Bytes.fs Error.fs tcp.fs RSA.fs Principal.fs Algorithms.fs CipherSuites.fs formats.fs TLSInfo.fs HASH.fs HMAC.fs MAC.fs TLSPlain.fs ENC.fs AEAD.fs Stream.fs record.fs
#recordfs-a = Error.fs  tcp-a.fs  Sessions.fs  formats.fs CryptoTLS.fs record.fs 

dispatchfs7 = AppCommon.fs7 PRFs.fs7 SessionDB.fs7 HS_msg.fs7 Handshake.fs7 AppData.fs7 Alert.fs7 Dispatch.fs7
dispatchfsi = AppCommon.fsi PRFs.fsi SessionDB.fsi HS_msg.fsi Handshake.fsi AppData.fsi Alert.fsi Dispatch.fsi
dispatchfs = AppCommon.fs PRFs.fs SessionDB.fs HS_msg.fs Handshake.fs AppData.fs Alert.fs Dispatch.fs

tlsfs7 = TLS.fs7
tlsfsi = TLS.fsi
tlsfs = TLS.fs

clib=../../../lib/concrete-fs/
slib=../../../lib/symbolic/
ilib=../../../lib/interfaces/
lpi= $(ilib)pi.mli $(slib)pi.ml

intfs = $(ilib)formulas.mli 


#libs= $(clib)pi.fs $(intfs) $(clib)formulas.fs $(clib)db.fs $(clib)data.fs $(clib)crypto.fs $(clib)xml.fs $(clib)net.fs $(clib)bytearray.fs
libs= $(clib)formulas.fs $(clib)pi.fs
libs-a= $(intfs) $(slib)formulas.ml
libs-a-pr= $(lpi) $(slib)formulas.ml

libsym-a.dll: $(lpi) $(libs-a) # building DLLs, e.g. for intellisense integration
	$(fsc) $(lpi) $(libs-a) -a -o $@

libsym.dll: $(libs)
	$(fsc) -d concrete $(libs) -a -o libsym.dll

record.dll: libsym.dll $(recordfsi) $(recordfs)
	$(fsc) -d concrete -r $^ -a -o record.dll

Dispatch.dll: libsym.dll record.dll $(dispatchsi) $(dispatchfs)
	$(fsc) -r libsym.dll -r record.dll $(dispatchfsi) $(dispatchfs) -a -o Dispatch.dll

TLS.dll: libsym.dll record.dll Dispatch.dll $(tlsfsi) $(tlsfs)
	$(fsc) -r libsym.dll -r record.dll -r Dispatch.dll $(tlsfsi) $(tlsfs) -a -o TLS.dll

recordsig.fs7: libsym.dll $(recordfsi) $(recordfs-a)
	$(fsc) -r $^ -a --sig:recordsig.fs7 -o recordsig.dll

Dispatchsig.fs7: libsym.dll record-a.dll $(dispatchfsi) $(dispatchfs)
	$(fsc) -r libsym.dll -r record-a.dll $(dispatchfsi) $(dispatchfs) -a --sig:Dispatchsig.fs7 -o Dispatchsig.dll

record-a.dll: libsym-a.dll $(recordfsi) $(recordfs-a)
	$(fsc) -r $^ -a -o record-a.dll

Dispatch-a.dll: libsym-a.dll record-a.dll $(tlsfsi) $(tlsfs)
	$(fsc) -r libsym-a.dll -r record-a.dll $(tlsfsi) $(tlsfs) -a -o Dispatch-a.dll

### f7 typechecking, in the same order as in VS 

#CF not sure what the default rule was doing, now more bespoke

tc7:: Algorithms.tc7 CipherSuites.tc7 formats.tc7 TLSInfo.tc7 HASH.tc7 HMAC.tc7 TLSPlain.tc7 ENC.tc7 AEAD.tc7 Stream.tc7 record.tc7 AppCommon.tc7 PRFs.tc7 SessionDB.tc7 Handshake.tc7 AppData.tc7 Alert.tc7 dispatch.tc7 TLS.tc7

f7t= echo ; $(f7) -nokindcheck --verbose $(lperv) $(libfs7)

Error.tc7: $(libperv) $(libfs7) Error.fs7 Error.fs
	$(f7t) Error.fs7 Error.fs

# trusting Bytes.fs7 (could be partly verified)
# trusting tcp.fs7 
# trusting RSA.fs7 (mostly calling System.Security.Cryptography)
# trusting Principal.fs7 

Algorithms.tc7: $(libperv) $(libfs7) Bytes.fs7 Algorithms.fs7 Algorithms.fs
	$(f7t) Bytes.fs7 Algorithms.fs7 Algorithms.fs -scripts Algorithms

# FIXME does not verify because of enums.
CipherSuites.tc7: $(libperv) $(libfs7) Bytes.fs7 Algorithms.fs7 Error.fs7 CipherSuites.fs7 CipherSuites.fs
	$(f7t) -scripts CipherSuites Bytes.fs7 Algorithms.fs7 Error.fs7 CipherSuites.fs7 CipherSuites.fs 

formats.tc7: $(libperv) $(libfs7) Bytes.fs7 Error.fs7 formats.fs7 formats.fs
	$(f7t) -scripts formats Bytes.fs7 Error.fs7 formats.fs7 formats.fs 

TLSInfo.tc7: $(libperv) $(libfs7) Bytes.fs7 Error.fs7 Principal.fs7 TLSInfo.fs7 TLSInfo.fs
	$(f7t) Bytes.fs7 Error.fs7 RSA.fs7 Principal.fs7 Algorithms.fs7 CipherSuites.fs7 TLSInfo.fs7 TLSInfo.fs

# trusting HASH.fs7 (mostly calling System.Security.Cryptography)
# trusting HMAC.fs7 (mostly calling System.Security.Cryptography)
	
MAC.tc7: $(libperv) $(libfs7) Bytes.fs7 Algorithms.fs7 Ciphersuites.fs7 Error.fs7 HASH.fs7 HMAC.fs7 MAC.fs7 MAC.fs
	$(f7t) --verbose Bytes.fs7 Algorithms.fs7 Ciphersuites.fs7 Error.fs7 HASH.fs7 HMAC.fs7 MAC.fs7 MAC.fs

Alert.tc7: $(libperv) $(libfs7) Bytes.fs7 Error.fs7 RSA.fs7 Principal.fs7 Algorithms.fs7 CipherSuites.fs7 formats.fs7 TLSInfo.fs7 TLSPlain.fs7 Alert.fs7 Alert.fs 
	$(f7t) Bytes.fs7 Error.fs7 RSA.fs7 Principal.fs7 Algorithms.fs7 CipherSuites.fs7 formats.fs7 TLSInfo.fs7 TLSPlain.fs7 Alert.fs7 Alert.fs 

# trusting SessionDB (unnecessarily?)

HS_msg.tc7: $(libperv) $(libfs7)  Bytes.fs7 Error.fs7 RSA.fs7 Principal.fs7 Algorithms.fs7 CipherSuites.fs7 formats.fs7 TLSInfo.fs7 HS_msg.fsi HS_msg.fs 
	$(f7t) Bytes.fs7 Error.fs7 RSA.fs7 Principal.fs7 Algorithms.fs7 CipherSuites.fs7 formats.fs7 TLSInfo.fs7 HS_msg.fsi HS_msg.fs 

Handshake.tc7: $(libperv) $(libfs7) Bytes.fs7 Error.fs7 RSA.fs7 Principal.fs7 Algorithms.fs7 CipherSuites.fs7 formats.fs7 TLSInfo.fs7 Handshake.fs7 Handshake.fs 
	$(f7t) Bytes.fs7 Error.fs7 RSA.fs7 Principal.fs7 Algorithms.fs7 CipherSuites.fs7 formats.fs7 TLSInfo.fs7 Handshake.fs7 Handshake.fs 

record.tc7: $(libperv) $(libfs7) $(recordfs7) record.fs
	$(f7) -debug -nofstypecheck -timeout 30 --define f7 -nokindcheck $(lperv) $(libfs7) $(recordfs7) record.fs -scripts record 

#CF ? 
autogen.fsi: $(libperv) $(libfs7) $(recordfs7) record.fs
	$(f7) -nofstypecheck -timeout 300 --define f7 -genfsi -fsifile autogen.fsi -genprotofs -protofsfile autogen.fs -nokindcheck $(lperv) $(libfs7) $(recordfs7) record.fs 

Sessions.tc7: $(libperv) $(libfs7) $(recordfs7) Sessions.fs
	$(f7) -timeout 20 --define f7 -nokindcheck $(lperv) $(libfs7) $(recordfs7) Sessions.fs -scripts Sessions -genlst | tee  Sessions.tc7 | grep "Failure\|error\|ERROR\|Exception"; echo ""

#formats.tc7: $(libperv) $(libfs7) $(recordfs7) formats.fs
#	time $(f7) -timeout 20 --define f7 -nokindcheck $(lperv) $(libfs7) $(recordfs7) formats.fs -scripts formats -genlst | tee  formats.tc7 | grep "Failure\|error\|ERROR\|Exception"; echo ""

AppData.tc7: $(libperv) $(libfs7) $(recordfs7) AppData.fs7 AppData.fs 
	$(f7) -timeout 200 --define f7 -nokindcheck $(lperv) $(libfs7) $(recordfs7) AppData.fs7 AppData.fs -scripts AppData -genlst | tee AppData.tc7 | grep "Failure\|error\|ERROR\|Exception"; echo ""

%.tc7: $(libperv) $(libfs7) $(recordfs7) $(tlsfs7) %.fs
	time $(f7) -nofstypecheck -timeout 30 --define f7 -nokindcheck $(lperv) $(libfs7) $(recordfs7) $(tlsfs7) $*.fs -scripts $* -genlst | tee  $*.tc7 | grep "Failure\|error\|ERROR\|Exception"; echo ""

clean:
	@rm -f .tmp *.exe *.pdb *.dll *.obj *.cm* *.pv *.res *~ *.html *.smp *.tc7 *.vo *.glob libcoq.v
