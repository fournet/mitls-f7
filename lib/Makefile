include ../../../../Makefile.inc

all: tls.dll tlsbase-tc7 tls# tlsapplication-tc7 crypto-tc7 tlsrecord-tc7

lib7=../../../lib/fs7-interfaces/
libperv = $(lib7)pervasives.fs7 $(lib7)tuples.fs7
lperv = -pervasives $(lib7)pervasives.fs7 -tuples $(lib7)tuples.fs7
libfs7 = $(lib7)formulas.fs7 $(lib7)pi.fs7

recordfs7 = Error.fs7 Bytes.fs7 tcp.fs7 RSA.fs7 Principal.fs7 Algorithms.fs7 CipherSuites.fs7 formats.fs7 TLSInfo.fs7 HASH.fs7 HMAC.fs7 ENCKey.fs7 MACKey.fs7 PRFs.fs7 TLSKey.fs7 AppCommon.fs7 SessionDB.fs7 FragCommon.fs7 AppDataPlain.fs7 AppData.fs7 HS_msg.fs7 Handshake.fs7 Alert.fs7 TLSFragment.fs7 MACPlain.fs7 Plain.fs7 MAC.fs7 ENC.fs7 AEAD.fs7 record.fs7
recordfsi = Error.fsi Bytes.fsi tcp.fsi RSA.fsi Principal.fsi Algorithms.fsi CipherSuites.fsi formats.fsi TLSInfo.fsi HASH.fsi HMAC.fsi ENCKey.fsi MACKey.fsi PRFs.fsi TLSKey.fsi AppCommon.fsi SessionDB.fsi FragCommon.fsi AppDataPlain.fsi AppData.fsi HS_msg.fsi Handshake.fsi Alert.fsi TLSFragment.fsi MACPlain.fsi Plain.fsi MAC.fsi ENC.fsi AEAD.fsi record.fsi

recordfs  = Error.fs  Bytes.fs  tcp.fs  RSA.fs  Principal.fs  Algorithms.fs  CipherSuites.fs  formats.fs  TLSInfo.fs  HASH.fs  HMAC.fs  ENCKey.fs  MACKey.fs  PRFs.fs  TLSKey.fs   TLSFragment.fs  MACPlain.fs  Plain.fs  MAC.fs  ENC.fs  AEAD.fs  record.fs

wrapperlibs = Error.fs  Bytes.fs  tcp.fs Algorithms.fs RSA.fs  HASH.fs  HMAC.fs  Principal.fs  # not verified 
tlsbase = CipherSuites.fs  formats.fs  TLSInfo.fs  ENCKey.fs  MACKey.fs TLSKey.fs # verified
tlshandshake = AppCommon.fs PRFs.fs SessionDB.fs FragCommon.fs HS_msg.fs  Handshake.fs  Alert.fs  # todo
tlsapplication = AppDataPlain.fs  AppData.fs  TLSFragment.fs MACPlain.fs Plain.fs # being verified (KB)
crypto =  MAC.fs ENC.fs AEAD.fs # verified? (CF)
tlsrecord = record.fs dispatch.fs tls.fs # being verified (AP)

wrapperlibsi = Error.fsi  Bytes.fsi  tcp.fsi  Algorithms.fsi  RSA.fsi  HASH.fsi  HMAC.fsi  Principal.fsi  # not verified 
tlsbasei = CipherSuites.fsi  formats.fsi  TLSInfo.fsi  ENCKey.fsi  MACKey.fsi TLSKey.fsi # verified
tlshandshakei = AppCommon.fsi  PRFs.fsi SessionDB.fsi FragCommon.fsi HS_msg.fsi  Handshake.fsi  Alert.fsi  # todo
tlsapplicationi = AppDataPlain.fsi  AppData.fsi  TLSFragment.fsi MACPlain.fsi Plain.fsi # being verified (KB)
cryptoi =  MAC.fsi ENC.fsi AEAD.fsi # verified? (CF)
tlsrecordi = record.fsi dispatch.fsi tls.fsi # being verified (AP)

tlsbase-tc7: Error.tc7 Algorithms.tc7 CipherSuites.tc7  formats.tc7  TLSInfo.tc7  ENCKey.tc7  MACKey.tc7 TLSKey.tc7 # verified
tlsapplication-tc7: AppDataPlain.tc7  AppData.tc7  TLSFragment.tc7 MACPlain.tc7 Plain.tc7 
crypto-tc7: MAC.tc7 ENC.tc7 AEAD.tc7
tlsrecord-tc7: record.tc7 dispatch.tc7 tls.tc7

#recordfs-a = Error.fs  tcp-a.fs  Sessions.fs  formats.fs CryptoTLS.fs record.fs 

dispatchfs7 = Dispatch.fs7
dispatchfsi = Dispatch.fsi
dispatchfs  = Dispatch.fs

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

wrapperlibs.dll: libsym.dll $(wrapperlibsi) $(wrapperlibs)
	$(fsc) -d concrete -r $^ -a -o $@

tlsbase.dll: libsym.dll wrapperlibs.dll $(tlsbasei) $(tlsbase)
	$(fsc) -d concrete -r libsym.dll -r wrapperlibs.dll $(tlsbasei) $(tlsbase) -a -o $@

tlshandshake.dll: libsym.dll wrapperlibs.dll tlsbase.dll  $(tlshandshakei) $(tlshandshake)
	$(fsc) -d concrete -r libsym.dll -r wrapperlibs.dll -r tlsbase.dll  $(tlshandshakei) $(tlshandshake) -a -o $@

tlsapplication.dll: libsym.dll wrapperlibs.dll tlsbase.dll tlshandshake.dll $(tlsapplicationi) $(tlsapplication)
	$(fsc) -d concrete -r libsym.dll -r wrapperlibs.dll -r tlsbase.dll -r tlshandshake.dll $(tlsapplicationi) $(tlsapplication) -a -o $@

crypto.dll: libsym.dll wrapperlibs.dll tlsbase.dll  tlshandshake.dll tlsapplication.dll $(cryptoi) $(crypto)
	$(fsc) -d concrete -r  libsym.dll -r wrapperlibs.dll -r tlsbase.dll -r tlshandshake.dll -r tlsapplication.dll $(cryptoi) $(crypto) -a -o $@

tls.dll: libsym.dll wrapperlibs.dll tlsbase.dll  tlshandshake.dll tlsapplication.dll crypto.dll $(tlsrecordi) $(tlsrecord)
	$(fsc) -d concrete -r libsym.dll -r wrapperlibs.dll -r tlsbase.dll -r tlshandshake.dll -r tlsapplication.dll -r crypto.dll $(tlsrecordi) $(tlsrecord) -a -o $@

record.dll: libsym.dll $(recordfsi) $(recordfs)
	$(fsc) -d concrete -r $^ -a -o record.dll

Dispatch.dll: libsym.dll record.dll $(dispatchsi) $(dispatchfs)
	$(fsc) -r libsym.dll -r record.dll $(dispatchfsi) $(dispatchfs) -a -o Dispatch.dll

TLS-old.dll: libsym.dll record.dll Dispatch.dll $(tlsfsi) $(tlsfs)
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


# Compilation Order: WRAPPERLIBS TLSCRYPTO CRYPTO TLSRECORD TLSCONFIG 

tc7:: Algorithms.tc7 CipherSuites.tc7 formats.tc7 TLSInfo.tc7 TLSFragment.tc7 MACKey.tc7 ENCKey.tc7 TLSKey.tc7
# TODO for TLS Record: (KB:) AppDataPlain.tc7 AppData.tc7 (Alfredo:) Dispatch.tc7 TLS.tc7 
# TODO for TLS Full: FragCommon.fs HS_msg.tc7 Handshake.tc7 Alert.tc7 
# TODO for CRYPTO: MACPlain.tc7 Plain.tc7 MAC.tc7 ENC.tc7 AEAD.tc7 

# NOT VERIFIED LIBS: Error.fs Bytes.fs tcp.fs Principal.fs 
# NOT VERIFIED CRYPTO LIBS: RSA.fs HASH.fs HMAC.fs PRFs.fs 
# NOT VERIFIED TLS: AppCommon.fs SessionDB.fs 

f7t= echo ; $(f7) -nokindcheck $(lperv) $(libfs7)

Error.tc7: $(libperv) $(libfs7) Error.fs7 Error.fs
	$(f7t) Error.fs7 Error.fs

# trusting Bytes.fs7 (could be partly verified)
# trusting tcp.fs7 
# trusting RSA.fs7 (mostly calling System.Security.Cryptography)
# trusting Principal.fs7 

Algorithms.tc7: $(libperv) $(libfs7) Bytes.fs7 Algorithms.fs7 Algorithms.fs
	$(f7t) Bytes.fs7 Algorithms.fs7 Algorithms.fs -scripts Algorithms

CipherSuites.tc7: $(libperv) $(libfs7) Bytes.fs7 Algorithms.fs7 Error.fs7 CipherSuites.fs7 CipherSuites.fs
	$(f7t) -scripts CipherSuites Bytes.fs7 Algorithms.fs7 Error.fs7 CipherSuites.fs7 CipherSuites.fs 

formats.tc7: $(libperv) $(libfs7) Bytes.fs7 Error.fs7 formats.fs7 formats.fs
	$(f7t) -scripts formats Bytes.fs7 Error.fs7 formats.fs7 formats.fs 

TLSInfo.tc7: $(libperv) $(libfs7) Bytes.fs7 Error.fs7 Principal.fs7 TLSInfo.fs7 TLSInfo.fs
	$(f7t) -scripts TLSInfo Bytes.fs7 Error.fs7 RSA.fs7 Principal.fs7 Algorithms.fs7 CipherSuites.fs7 TLSInfo.fs7 TLSInfo.fs

# trusting HASH.fs7 (mostly calling System.Security.Cryptography)
# trusting HMAC.fs7 (mostly calling System.Security.Cryptography)

ENCKey.tc7: $(libperv) $(libfs7) Bytes.fs7 Algorithms.fs7 Error.fs7 RSA.fs7 Principal.fs7  Ciphersuites.fs7 TLSInfo.fs7 EncKey.fs7 EncKey.fs
	$(f7t) Bytes.fs7 Algorithms.fs7 Error.fs7 RSA.fs7 Principal.fs7 Ciphersuites.fs7 TLSInfo.fs7 EncKey.fs7 EncKey.fs

MACKey.tc7: $(libperv) $(libfs7) Bytes.fs7 Error.fs7 RSA.fs7 Principal.fs7 Algorithms.fs7 Ciphersuites.fs7 TLSInfo.fs7 MACKey.fs7 MACKey.fs
	$(f7t) Bytes.fs7 Error.fs7 RSA.fs7 Principal.fs7 Algorithms.fs7 Ciphersuites.fs7 TLSInfo.fs7 MACKey.fs7 MACKey.fs

# trusting PRFs.fs7 (mostly calling System.Security.Cryptography)

TLSKey.tc7: $(libperv) $(libfs7) Bytes.fs7 Algorithms.fs7 Error.fs7 Principal.fs7 Ciphersuites.fs7 TLSInfo.fs7 ENCKey.fs7 MACKey.fs7 TLSKey.fs7 TLSKey.fs
	$(f7t) Error.fs7 Bytes.fs7  RSA.fs7 Principal.fs7 Algorithms.fs7 Ciphersuites.fs7 TLSInfo.fs7 ENCKey.fs7 MACKey.fs7 TLSKey.fs7 TLSKey.fs

# FIMXE: AppCommon uses System.TimeSpan. We might want to trust the implementation, but we need refinement types for the record fields!
AppCommon.tc7: $(libperv) $(libfs7) Bytes.fs7 Principal.fs7 Algorithms.fs7 Ciphersuites.fs7 TLSInfo.fs7 AppCommon.fs7 AppCommon.fs
	$(f7t) Bytes.fs7 Principals.fs7 Algorithms.fs7 Ciphersuites.fs7 TLSInfo.fs7 AppCommon.fs7 AppCommon.fs

# trusting SessionDB.fs7

# trusting FragCommon.fs7 (where we assume the CompatibleLength predicate)
#FragCommon.tc7: $(libperv) $(libfs7) Bytes.fs7 Algorithms.fs7 Ciphersuites.fs7 TLSInfo.fs7 FragCommon.fs7 FragCommon.fs
#	$(f7t) Bytes.fs7 Algorithms.fs7 Ciphersuites.fs7 TLSInfo.fs7 FragCommon.fs7 FragCommon.fs

AppDataPlain.tc7: $(libperv) $(libfs7) Error.fs7 Bytes.fs7 tcp.fs7 RSA.fs7 Principal.fs7 Algorithms.fs7 CipherSuites.fs7 formats.fs7 TLSInfo.fs7 HASH.fs7 HMAC.fs7 ENCKey.fs7 MACKey.fs7 PRFs.fs7 TLSKey.fs7 AppCommon.fs7 SessionDB.fs7 FragCommon.fs7 AppDataPlain.fs7 AppDataPlain.fs
	$(f7t) Error.fs7 Bytes.fs7 tcp.fs7 RSA.fs7 Principal.fs7 Algorithms.fs7 CipherSuites.fs7 formats.fs7 TLSInfo.fs7 HASH.fs7 HMAC.fs7 ENCKey.fs7 MACKey.fs7 PRFs.fs7 TLSKey.fs7 AppCommon.fs7 SessionDB.fs7 FragCommon.fs7 AppDataPlain.fs7 AppDataPlain.fs

AppData.tc7: $(libperv) $(libfs7) Error.fs7 Bytes.fs7 tcp.fs7 RSA.fs7 Principal.fs7 Algorithms.fs7 CipherSuites.fs7 formats.fs7 TLSInfo.fs7 HASH.fs7 HMAC.fs7 ENCKey.fs7 MACKey.fs7 PRFs.fs7 TLSKey.fs7 AppCommon.fs7 SessionDB.fs7 FragCommon.fs7 AppDataPlain.fs7 AppData.fs7 AppData.fs
	$(f7t) Error.fs7 Bytes.fs7 tcp.fs7 RSA.fs7 Principal.fs7 Algorithms.fs7 CipherSuites.fs7 formats.fs7 TLSInfo.fs7 HASH.fs7 HMAC.fs7 ENCKey.fs7 MACKey.fs7 PRFs.fs7 TLSKey.fs7 AppCommon.fs7 SessionDB.fs7 FragCommon.fs7 AppDataPlain.fs7 AppData.fs7 AppData.fs

HS_msg.tc7: $(libperv) $(libfs7) Error.fs7 Bytes.fs7 RSA.fs7 Principal.fs7 Algorithms.fs7 Ciphersuites.fs7 formats.fs7 TLSInfo.fs7 HASH.fs7 HMAC.fs7 ENCKey.fs7 MACKey.fs7 PRFs.fs7 TLSKey.fs7 AppCommon.fs7 SessionDB.fs7 FragCommon.fs7 HS_msg.fs7 HS_msg.fs
	$(f7t) Error.fs7 Bytes.fs7 RSA.fs7 Principal.fs7 Algorithms.fs7 Ciphersuites.fs7 formats.fs7 TLSInfo.fs7 HASH.fs7 HMAC.fs7 ENCKey.fs7 MACKey.fs7 PRFs.fs7 TLSKey.fs7 AppCommon.fs7 SessionDB.fs7 FragCommon.fs7 HS_msg.fs7 HS_msg.fs

Handshake.tc7: $(libperv) $(libfs7) Error.fs7 Bytes.fs7 RSA.fs7 Principal.fs7 Algorithms.fs7 Ciphersuites.fs7 formats.fs7 TLSInfo.fs7 HASH.fs7 HMAC.fs7 ENCKey.fs7 MACKey.fs7 PRFs.fs7 TLSKey.fs7 AppCommon.fs7 SessionDB.fs7 FragCommon.fs7 HS_msg.fs7 Handshake.fs7 Handshake.fs
	$(f7t) Error.fs7 Bytes.fs7 RSA.fs7 Principal.fs7 Algorithms.fs7 Ciphersuites.fs7 formats.fs7 TLSInfo.fs7 HASH.fs7 HMAC.fs7 ENCKey.fs7 MACKey.fs7 PRFs.fs7 TLSKey.fs7 AppCommon.fs7 SessionDB.fs7 FragCommon.fs7 HS_msg.fs7 Handshake.fs7 Handshake.fs

Alert.tc7: $(libperv) $(libfs7) Error.fs7 Bytes.fs7 tcp.fs7 RSA.fs7 Principal.fs7 Algorithms.fs7 CipherSuites.fs7 formats.fs7 TLSInfo.fs7 HASH.fs7 HMAC.fs7 ENCKey.fs7 MACKey.fs7 PRFs.fs7 TLSKey.fs7 AppCommon.fs7 SessionDB.fs7 FragCommon.fs7 Alert.fs7 Alert.fs
	$(f7t) Error.fs7 Bytes.fs7 tcp.fs7 RSA.fs7 Principal.fs7 Algorithms.fs7 CipherSuites.fs7 formats.fs7 TLSInfo.fs7 HASH.fs7 HMAC.fs7 ENCKey.fs7 MACKey.fs7 PRFs.fs7 TLSKey.fs7 AppCommon.fs7 SessionDB.fs7 FragCommon.fs7 Alert.fs7 Alert.fs

TLSFragment.tc7: $(libperv) $(libfs7) Error.fs7 Bytes.fs7 tcp.fs7 RSA.fs7 Principal.fs7 Algorithms.fs7 CipherSuites.fs7 formats.fs7 TLSInfo.fs7 HASH.fs7 HMAC.fs7 ENCKey.fs7 MACKey.fs7 PRFs.fs7 TLSKey.fs7 AppCommon.fs7 SessionDB.fs7 FragCommon.fs7 AppDataPlain.fs7 AppData.fs7 HS_msg.fs7 Handshake.fs7 Alert.fs7 TLSFragment.fs7 TLSFragment.fs
	$(f7t) Error.fs7 Bytes.fs7 tcp.fs7 RSA.fs7 Principal.fs7 Algorithms.fs7 CipherSuites.fs7 formats.fs7 TLSInfo.fs7 HASH.fs7 HMAC.fs7 ENCKey.fs7 MACKey.fs7 PRFs.fs7 TLSKey.fs7 AppCommon.fs7 SessionDB.fs7 FragCommon.fs7 AppDataPlain.fs7 AppData.fs7 HS_msg.fs7 Handshake.fs7 Alert.fs7 TLSFragment.fs7 TLSFragment.fs -scripts TLSFragment

MACPlain.tc7: $(libperv) $(libfs7) Error.fs7 Bytes.fs7 tcp.fs7 RSA.fs7 Principal.fs7 Algorithms.fs7 CipherSuites.fs7 formats.fs7 TLSInfo.fs7 HASH.fs7 HMAC.fs7 ENCKey.fs7 MACKey.fs7 PRFs.fs7 TLSKey.fs7 AppCommon.fs7 SessionDB.fs7 FragCommon.fs7 AppDataPlain.fs7 AppData.fs7 HS_msg.fs7 Handshake.fs7 Alert.fs7 TLSFragment.fs7 MACPlain.fs7 MACPlain.fs
	$(f7t) -scripts MACPlain Error.fs7 Bytes.fs7 tcp.fs7 RSA.fs7 Principal.fs7 Algorithms.fs7 CipherSuites.fs7 formats.fs7 TLSInfo.fs7 HASH.fs7 HMAC.fs7 ENCKey.fs7 MACKey.fs7 PRFs.fs7 TLSKey.fs7 AppCommon.fs7 SessionDB.fs7 FragCommon.fs7 AppDataPlain.fs7 AppData.fs7 HS_msg.fs7 Handshake.fs7 Alert.fs7 TLSFragment.fs7 MACPlain.fs7 MACPlain.fs

Plain.tc7: $(libperv) $(libfs7) Error.fs7 Bytes.fs7 tcp.fs7 RSA.fs7 Principal.fs7 Algorithms.fs7 CipherSuites.fs7 formats.fs7 TLSInfo.fs7 HASH.fs7 HMAC.fs7 ENCKey.fs7 MACKey.fs7 PRFs.fs7 TLSKey.fs7 AppCommon.fs7 SessionDB.fs7 FragCommon.fs7 AppDataPlain.fs7 AppData.fs7 HS_msg.fs7 Handshake.fs7 Alert.fs7 TLSFragment.fs7 MACPlain.fs7 Plain.fs7 Plain.fs
	$(f7t) -scripts Plain Error.fs7 Bytes.fs7 tcp.fs7 RSA.fs7 Principal.fs7 Algorithms.fs7 CipherSuites.fs7 formats.fs7 TLSInfo.fs7 HASH.fs7 HMAC.fs7 ENCKey.fs7 MACKey.fs7 PRFs.fs7 TLSKey.fs7 AppCommon.fs7 SessionDB.fs7 FragCommon.fs7 AppDataPlain.fs7 AppData.fs7 HS_msg.fs7 Handshake.fs7 Alert.fs7 TLSFragment.fs7 MACPlain.fs7 Plain.fs7 Plain.fs

MAC.tc7: $(libperv) $(libfs7) Error.fs7 Bytes.fs7 tcp.fs7 RSA.fs7 Principal.fs7 Algorithms.fs7 CipherSuites.fs7 formats.fs7 TLSInfo.fs7 HASH.fs7 HMAC.fs7 ENCKey.fs7 MACKey.fs7 PRFs.fs7 TLSKey.fs7 AppCommon.fs7 SessionDB.fs7 FragCommon.fs7 AppDataPlain.fs7 AppData.fs7 HS_msg.fs7 Handshake.fs7 Alert.fs7 TLSFragment.fs7 MACPlain.fs7 Plain.fs7 MAC.fs7 MAC.fs
	$(f7t) Error.fs7 Bytes.fs7 tcp.fs7 RSA.fs7 Principal.fs7 Algorithms.fs7 CipherSuites.fs7 formats.fs7 TLSInfo.fs7 HASH.fs7 HMAC.fs7 ENCKey.fs7 MACKey.fs7 PRFs.fs7 TLSKey.fs7 AppCommon.fs7 SessionDB.fs7 FragCommon.fs7 AppDataPlain.fs7 AppData.fs7 HS_msg.fs7 Handshake.fs7 Alert.fs7 TLSFragment.fs7 MACPlain.fs7 Plain.fs7 MAC.fs7 MAC.fs

ENC.tc7: $(libperv) $(libfs7) Error.fs7 Bytes.fs7 tcp.fs7 RSA.fs7 Principal.fs7 Algorithms.fs7 CipherSuites.fs7 formats.fs7 TLSInfo.fs7 HASH.fs7 HMAC.fs7 ENCKey.fs7 MACKey.fs7 PRFs.fs7 TLSKey.fs7 AppCommon.fs7 SessionDB.fs7 FragCommon.fs7 AppDataPlain.fs7 AppData.fs7 HS_msg.fs7 Handshake.fs7 Alert.fs7 TLSFragment.fs7 MACPlain.fs7 Plain.fs7 MAC.fs7 ENC.fs7 ENC.fs
	$(f7t) Error.fs7 Bytes.fs7 tcp.fs7 RSA.fs7 Principal.fs7 Algorithms.fs7 CipherSuites.fs7 formats.fs7 TLSInfo.fs7 HASH.fs7 HMAC.fs7 ENCKey.fs7 MACKey.fs7 PRFs.fs7 TLSKey.fs7 AppCommon.fs7 SessionDB.fs7 FragCommon.fs7 AppDataPlain.fs7 AppData.fs7 HS_msg.fs7 Handshake.fs7 Alert.fs7 TLSFragment.fs7 MACPlain.fs7 Plain.fs7 MAC.fs7 ENC.fs7 ENC.fs

AEAD.tc7: $(libperv) $(libfs7) Error.fs7 Bytes.fs7 tcp.fs7 RSA.fs7 Principal.fs7 Algorithms.fs7 CipherSuites.fs7 formats.fs7 TLSInfo.fs7 HASH.fs7 HMAC.fs7 ENCKey.fs7 MACKey.fs7 PRFs.fs7 TLSKey.fs7 AppCommon.fs7 SessionDB.fs7 FragCommon.fs7 AppDataPlain.fs7 AppData.fs7 HS_msg.fs7 Handshake.fs7 Alert.fs7 TLSFragment.fs7 MACPlain.fs7 Plain.fs7 MAC.fs7 ENC.fs7 AEAD.fs7 AEAD.fs
	$(f7t) Error.fs7 Bytes.fs7 tcp.fs7 RSA.fs7 Principal.fs7 Algorithms.fs7 CipherSuites.fs7 formats.fs7 TLSInfo.fs7 HASH.fs7 HMAC.fs7 ENCKey.fs7 MACKey.fs7 PRFs.fs7 TLSKey.fs7 AppCommon.fs7 SessionDB.fs7 FragCommon.fs7 AppDataPlain.fs7 AppData.fs7 HS_msg.fs7 Handshake.fs7 Alert.fs7 TLSFragment.fs7 MACPlain.fs7 Plain.fs7 MAC.fs7 ENC.fs7

# FIXME: Stream.fs7 is currently unused. Remove from project? Indeed, AppDataPlain should inherit its refinements

record.tc7: $(libperv) $(libfs7) $(recordfs7) record.fs
	$(f7t) -genprotofs -protofsfile proto.ml -scripts record $(recordfs7) record.fs

Dispatch.tc7: $(libperv) $(libfs7) $(recordfs7) Dispatch.fs7 Dispatch.fs
	$(f7t) -scripts Dispatch $(recordfs7) Dispatch.fs7 Dispatch.fs | tee Dispatch.tc7

TLS.tc7: $(libperv) $(libfs7) $(recordfs7) Dispatch.fs7 TLS.fs7 TLS.fs
	$(f7t) $(recordfs7) Dispatch.fs7 TLS.fs7 TLS.fs
#CF ? 
autogen.fsi: $(libperv) $(libfs7) $(recordfs7) record.fs
	$(f7) -nofstypecheck -timeout 300 --define f7 -genfsi -fsifile autogen.fsi -genprotofs -protofsfile autogen.fs -nokindcheck $(lperv) $(libfs7) $(recordfs7) record.fs 

clean:
	@rm -f .tmp *.exe *.pdb *.dll *.obj *.cm* *.pv *.res *~ *.html *.smp *.tc7 *.vo *.glob libcoq.v
