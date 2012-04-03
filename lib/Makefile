include ../../../../Makefile.inc

all: tls.dll tc7

lib7=../../../lib/fs7-interfaces/
libperv = $(lib7)pervasives.fs7 $(lib7)tuples.fs7
lperv = -pervasives $(lib7)pervasives.fs7 -tuples $(lib7)tuples.fs7
libfs7 = $(lib7)formulas.fs7 $(lib7)pi.fs7

wrapperlibs = Error.fs  Bytes.fs  tcp.fs Algorithms.fs RSA.fs  HASH.fs  HMAC.fs  Certificate.fs  # not verified 
tlsbase = CipherSuites.fs  formats.fs  TLSInfo.fs  MAC.fs # verified
plains = FragCommon.fs  DataStream.fs  HandshakePlain.fs  AlertPlain.fs  AppDataStream.fs  TLSFragment.fs  StatefulPlain.fs  AEADPlain.fs  AEPlain.fs
crypto =  ENC.fs AEAD.fs StatefulAEAD.fs # verified? (CF)
record = record.fs
tlsproto = Alert.fs  PRFs.fs  SessionDB.fs  Handshake.fs
dispatch = Dispatch.fs
toplevel = TLS.fs

wrapperlibsi = Error.fsi  Bytes.fsi  tcp.fsi Algorithms.fsi RSA.fsi  HASH.fsi  HMAC.fsi  Certificate.fsi  # not verified 
tlsbasei = CipherSuites.fsi  formats.fsi  TLSInfo.fsi  MAC.fsi # verified
plainsi = FragCommon.fsi  DataStream.fsi  HandshakePlain.fsi  AlertPlain.fsi  AppDataStream.fsi  TLSFragment.fsi  StatefulPlain.fsi  AEADPlain.fsi  AEPlain.fsi
cryptoi =  ENC.fsi AEAD.fsi StatefulAEAD.fsi # verified? (CF)
recordi = record.fsi
tlsprotoi = Alert.fsi  PRFs.fsi  SessionDB.fsi  Handshake.fsi
dispatchi = Dispatch.fsi
topleveli = TLS.fsi

wrapperlibs7 = Error.fs7  Bytes.fs7  tcp.fs7 Algorithms.fs7 RSA.fs7  HASH.fs7  HMAC.fs7  Certificate.fs7  # not verified 
tlsbase7 = CipherSuites.fs7  formats.fs7  TLSInfo.fs7  MAC.fs7 # verified
plains7 = FragCommon.fs7  DataStream.fs7  HandshakePlain.fs7  AlertPlain.fs7  AppDataStream.fs7  TLSFragment.fs7  StatefulPlain.fs7  AEADPlain.fs7  AEPlain.fs7
crypto7 =  ENC.fs7 AEAD.fs7 StatefulAEAD.fs7 # verified? (CF)
record7 = record.fs7
tlsproto7 = Alert.fs7  PRFs.fs7  SessionDB.fs7  Handshake.fs7
dispatch7 = Dispatch.fs7
toplevel7 = TLS.fs7

wrapperlibs-tc7: Error.tc7  Bytes.tc7  tcp.tc7 Algorithms.tc7 RSA.tc7  HASH.tc7  HMAC.tc7  Certificate.tc7  # not verified 
tlsbase-tc7: CipherSuites.tc7  formats.tc7  TLSInfo.tc7  MAC.tc7 # verified
plains-tc7: FragCommon.tc7  DataStream.tc7  HandshakePlain.tc7  AlertPlain.tc7  AppDataStream.tc7  TLSFragment.tc7  StatefulPlain.tc7  AEADPlain.tc7  AEPlain.tc7
crypto-tc7:  ENC.tc7 AEAD.tc7 StatefulAEAD.tc7 # verified? (CF)
record-tc7: record.tc7
tlsproto-tc7: Alert.tc7  PRFs.tc7  SessionDB.tc7  Handshake.tc7
dispatch-tc7: Dispatch.tc7
toplevel-tc7: TLS.tc7

#tc7:: tlsbase7 crypto7 tlsrecord-tc7

#recordfs-a = Error.fs  tcp-a.fs  Sessions.fs  formats.fs CryptoTLS.fs record.fs 

clib=../../../lib/concrete-fs/
slib=../../../lib/symbolic/
ilib=../../../lib/interfaces/
lpi= $(ilib)pi.mli $(slib)pi.ml

intfs = $(ilib)formulas.mli 

#libs= $(clib)pi.fs $(intfs) $(clib)formulas.fs $(clib)db.fs $(clib)data.fs $(clib)crypto.fs $(clib)xml.fs $(clib)net.fs $(clib)bytearray.fs
libs= $(clib)formulas.fs $(clib)pi.fs
libs-a= $(intfs) $(slib)formulas.ml
libs-a-pr= $(lpi) $(slib)formulas.ml

#libsym-a.dll: $(lpi) $(libs-a) # building DLLs, e.g. for intellisense integration
#	$(fsc) $(lpi) $(libs-a) -a -o $@

libsym.dll: $(libs)
	$(fsc) -d concrete $(libs) -a -o libsym.dll

wrapperlibs.dll: libsym.dll $(wrapperlibsi) $(wrapperlibs)
	$(fsc) -d concrete -r $^ -a -o $@

tlsbase.dll: libsym.dll wrapperlibs.dll $(tlsbasei) $(tlsbase)
	$(fsc) -d concrete -r libsym.dll -r wrapperlibs.dll $(tlsbasei) $(tlsbase) -a -o $@

plains.dll: libsym.dll wrapperlibs.dll tlsbase.dll $(plainsi) $(plains)
	$(fsc) -d concrete -r libsym.dll -r wrapperlibs.dll -r tlsbase.dll $(plainsi) $(plains) -a -o $@

crypto.dll: libsym.dll wrapperlibs.dll tlsbase.dll plains.dll $(cryptoi) $(crypto)
	$(fsc) -d concrete -r libsym.dll -r wrapperlibs.dll -r tlsbase.dll -r plains.dll $(cryptoi) $(crypto) -a -o $@

record.dll: libsym.dll wrapperlibs.dll tlsbase.dll plains.dll crypto.dll $(recordi) $(record)
	$(fsc) -d concrete -r libsym.dll -r wrapperlibs.dll -r tlsbase.dll -r plains.dll -r crypto.dll $(recordi) $(record) -a -o $@
	
tlsproto.dll: libsym.dll wrapperlibs.dll tlsbase.dll plains.dll crypto.dll record.dll $(tlsprotoi) $(tlsproto)
	$(fsc) -d concrete -r libsym.dll -r wrapperlibs.dll -r tlsbase.dll -r plains.dll -r crypto.dll -r record.dll $(tlsprotoi) $(tlsproto) -a -o $@
	
dispatch.dll: libsym.dll wrapperlibs.dll tlsbase.dll plains.dll crypto.dll record.dll tlsproto.dll $(dispatchi) $(dispatch)
	$(fsc) -d concrete -r libsym.dll -r wrapperlibs.dll -r tlsbase.dll -r plains.dll -r crypto.dll -r record.dll -r tlsproto.dll $(dispatchi) $(dispatch) -a -o $@

toplevel.dll: libsym.dll wrapperlibs.dll tlsbase.dll plains.dll crypto.dll record.dll tlsproto.dll dispatch.dll $(topleveli) $(toplevel)
	$(fsc) -d concrete -r libsym.dll -r wrapperlibs.dll -r tlsbase.dll -r plains.dll -r crypto.dll -r record.dll -r tlsproto.dll -r dispatch.dll $(topleveli) $(toplevel) -a -o $@

#recordsig.fs7: libsym.dll $(recordfsi) $(recordfs-a)
#	$(fsc) -r $^ -a --sig:recordsig.fs7 -o recordsig.dll

#Dispatchsig.fs7: libsym.dll record-a.dll $(dispatchfsi) $(dispatchfs)
#	$(fsc) -r libsym.dll -r record-a.dll $(dispatchfsi) $(dispatchfs) -a --sig:Dispatchsig.fs7 -o Dispatchsig.dll

#record-a.dll: libsym-a.dll $(recordfsi) $(recordfs-a)
#	$(fsc) -r $^ -a -o record-a.dll

#Dispatch-a.dll: libsym-a.dll record-a.dll $(tlsfsi) $(tlsfs)
#	$(fsc) -r libsym-a.dll -r record-a.dll $(tlsfsi) $(tlsfs) -a -o Dispatch-a.dll

### f7 typechecking, in the same order as in VS 

f7t= echo ; $(f7) -nokindcheck $(lperv) $(libfs7)

### BEGIN Autogenerated with "genrules"

Error.tc7: $(libperv) $(libfs7) Error.fs7 Error.fs
	 $(f7t) -scripts Error Error.fs7 Error.fs | tee Error.tc7

Bytes.tc7: $(libperv) $(libfs7) Error.fs7 Bytes.fs7 Bytes.fs
	 $(f7t) -scripts Bytes Error.fs7 Bytes.fs7 Bytes.fs | tee Bytes.tc7

tcp.tc7: $(libperv) $(libfs7) Error.fs7 Bytes.fs7 tcp.fs7 tcp.fs
	 $(f7t) -scripts tcp Error.fs7 Bytes.fs7 tcp.fs7 tcp.fs | tee tcp.tc7

Algorithms.tc7: $(libperv) $(libfs7) Error.fs7 Bytes.fs7 tcp.fs7 Algorithms.fs7 Algorithms.fs
	 $(f7t) -scripts Algorithms Error.fs7 Bytes.fs7 tcp.fs7 Algorithms.fs7 Algorithms.fs | tee Algorithms.tc7

RSA.tc7: $(libperv) $(libfs7) Error.fs7 Bytes.fs7 tcp.fs7 Algorithms.fs7 RSA.fs7 RSA.fs
	 $(f7t) -scripts RSA Error.fs7 Bytes.fs7 tcp.fs7 Algorithms.fs7 RSA.fs7 RSA.fs | tee RSA.tc7

HASH.tc7: $(libperv) $(libfs7) Error.fs7 Bytes.fs7 tcp.fs7 Algorithms.fs7 RSA.fs7 HASH.fs7 HASH.fs
	 $(f7t) -scripts HASH Error.fs7 Bytes.fs7 tcp.fs7 Algorithms.fs7 RSA.fs7 HASH.fs7 HASH.fs | tee HASH.tc7

HMAC.tc7: $(libperv) $(libfs7) Error.fs7 Bytes.fs7 tcp.fs7 Algorithms.fs7 RSA.fs7 HASH.fs7 HMAC.fs7 HMAC.fs
	 $(f7t) -scripts HMAC Error.fs7 Bytes.fs7 tcp.fs7 Algorithms.fs7 RSA.fs7 HASH.fs7 HMAC.fs7 HMAC.fs | tee HMAC.tc7

Certificate.tc7: $(libperv) $(libfs7) Error.fs7 Bytes.fs7 tcp.fs7 Algorithms.fs7 RSA.fs7 HASH.fs7 HMAC.fs7 Certificate.fs7 Certificate.fs
	 $(f7t) -scripts Certificate Error.fs7 Bytes.fs7 tcp.fs7 Algorithms.fs7 RSA.fs7 HASH.fs7 HMAC.fs7 Certificate.fs7 Certificate.fs | tee Certificate.tc7

CipherSuites.tc7: $(libperv) $(libfs7) Error.fs7 Bytes.fs7 tcp.fs7 Algorithms.fs7 RSA.fs7 HASH.fs7 HMAC.fs7 Certificate.fs7 CipherSuites.fs7 CipherSuites.fs
	 $(f7t) -scripts CipherSuites Error.fs7 Bytes.fs7 tcp.fs7 Algorithms.fs7 RSA.fs7 HASH.fs7 HMAC.fs7 Certificate.fs7 CipherSuites.fs7 CipherSuites.fs | tee CipherSuites.tc7

formats.tc7: $(libperv) $(libfs7) Error.fs7 Bytes.fs7 tcp.fs7 Algorithms.fs7 RSA.fs7 HASH.fs7 HMAC.fs7 Certificate.fs7 CipherSuites.fs7 formats.fs7 formats.fs
	 $(f7t) -scripts formats Error.fs7 Bytes.fs7 tcp.fs7 Algorithms.fs7 RSA.fs7 HASH.fs7 HMAC.fs7 Certificate.fs7 CipherSuites.fs7 formats.fs7 formats.fs | tee formats.tc7

TLSInfo.tc7: $(libperv) $(libfs7) Error.fs7 Bytes.fs7 tcp.fs7 Algorithms.fs7 RSA.fs7 HASH.fs7 HMAC.fs7 Certificate.fs7 CipherSuites.fs7 formats.fs7 TLSInfo.fs7 TLSInfo.fs
	 $(f7t) -scripts TLSInfo Error.fs7 Bytes.fs7 tcp.fs7 Algorithms.fs7 RSA.fs7 HASH.fs7 HMAC.fs7 Certificate.fs7 CipherSuites.fs7 formats.fs7 TLSInfo.fs7 TLSInfo.fs | tee TLSInfo.tc7

MAC.tc7: $(libperv) $(libfs7) Error.fs7 Bytes.fs7 tcp.fs7 Algorithms.fs7 RSA.fs7 HASH.fs7 HMAC.fs7 Certificate.fs7 CipherSuites.fs7 formats.fs7 TLSInfo.fs7 MAC.fs7 MAC.fs
	 $(f7t) -scripts MAC Error.fs7 Bytes.fs7 tcp.fs7 Algorithms.fs7 RSA.fs7 HASH.fs7 HMAC.fs7 Certificate.fs7 CipherSuites.fs7 formats.fs7 TLSInfo.fs7 MAC.fs7 MAC.fs | tee MAC.tc7

FragCommon.tc7: $(libperv) $(libfs7) Error.fs7 Bytes.fs7 tcp.fs7 Algorithms.fs7 RSA.fs7 HASH.fs7 HMAC.fs7 Certificate.fs7 CipherSuites.fs7 formats.fs7 TLSInfo.fs7 MAC.fs7 FragCommon.fs7 FragCommon.fs
	 $(f7t) -scripts FragCommon Error.fs7 Bytes.fs7 tcp.fs7 Algorithms.fs7 RSA.fs7 HASH.fs7 HMAC.fs7 Certificate.fs7 CipherSuites.fs7 formats.fs7 TLSInfo.fs7 MAC.fs7 FragCommon.fs7 FragCommon.fs | tee FragCommon.tc7

DataStream.tc7: $(libperv) $(libfs7) Error.fs7 Bytes.fs7 tcp.fs7 Algorithms.fs7 RSA.fs7 HASH.fs7 HMAC.fs7 Certificate.fs7 CipherSuites.fs7 formats.fs7 TLSInfo.fs7 MAC.fs7 FragCommon.fs7 DataStream.fs7 DataStream.fs
	 $(f7t) -scripts DataStream Error.fs7 Bytes.fs7 tcp.fs7 Algorithms.fs7 RSA.fs7 HASH.fs7 HMAC.fs7 Certificate.fs7 CipherSuites.fs7 formats.fs7 TLSInfo.fs7 MAC.fs7 FragCommon.fs7 DataStream.fs7 DataStream.fs | tee DataStream.tc7

HandshakePlain.tc7: $(libperv) $(libfs7) Error.fs7 Bytes.fs7 tcp.fs7 Algorithms.fs7 RSA.fs7 HASH.fs7 HMAC.fs7 Certificate.fs7 CipherSuites.fs7 formats.fs7 TLSInfo.fs7 MAC.fs7 FragCommon.fs7 DataStream.fs7 HandshakePlain.fs7 HandshakePlain.fs
	 $(f7t) -scripts HandshakePlain Error.fs7 Bytes.fs7 tcp.fs7 Algorithms.fs7 RSA.fs7 HASH.fs7 HMAC.fs7 Certificate.fs7 CipherSuites.fs7 formats.fs7 TLSInfo.fs7 MAC.fs7 FragCommon.fs7 DataStream.fs7 HandshakePlain.fs7 HandshakePlain.fs | tee HandshakePlain.tc7

AlertPlain.tc7: $(libperv) $(libfs7) Error.fs7 Bytes.fs7 tcp.fs7 Algorithms.fs7 RSA.fs7 HASH.fs7 HMAC.fs7 Certificate.fs7 CipherSuites.fs7 formats.fs7 TLSInfo.fs7 MAC.fs7 FragCommon.fs7 DataStream.fs7 HandshakePlain.fs7 AlertPlain.fs7 AlertPlain.fs
	 $(f7t) -scripts AlertPlain Error.fs7 Bytes.fs7 tcp.fs7 Algorithms.fs7 RSA.fs7 HASH.fs7 HMAC.fs7 Certificate.fs7 CipherSuites.fs7 formats.fs7 TLSInfo.fs7 MAC.fs7 FragCommon.fs7 DataStream.fs7 HandshakePlain.fs7 AlertPlain.fs7 AlertPlain.fs | tee AlertPlain.tc7

AppDataStream.tc7: $(libperv) $(libfs7) Error.fs7 Bytes.fs7 tcp.fs7 Algorithms.fs7 RSA.fs7 HASH.fs7 HMAC.fs7 Certificate.fs7 CipherSuites.fs7 formats.fs7 TLSInfo.fs7 MAC.fs7 FragCommon.fs7 DataStream.fs7 HandshakePlain.fs7 AlertPlain.fs7 AppDataStream.fs7 AppDataStream.fs
	 $(f7t) -scripts AppDataStream Error.fs7 Bytes.fs7 tcp.fs7 Algorithms.fs7 RSA.fs7 HASH.fs7 HMAC.fs7 Certificate.fs7 CipherSuites.fs7 formats.fs7 TLSInfo.fs7 MAC.fs7 FragCommon.fs7 DataStream.fs7 HandshakePlain.fs7 AlertPlain.fs7 AppDataStream.fs7 AppDataStream.fs | tee AppDataStream.tc7

TLSFragment.tc7: $(libperv) $(libfs7) Error.fs7 Bytes.fs7 tcp.fs7 Algorithms.fs7 RSA.fs7 HASH.fs7 HMAC.fs7 Certificate.fs7 CipherSuites.fs7 formats.fs7 TLSInfo.fs7 MAC.fs7 FragCommon.fs7 DataStream.fs7 HandshakePlain.fs7 AlertPlain.fs7 AppDataStream.fs7 TLSFragment.fs7 TLSFragment.fs
	 $(f7t) -scripts TLSFragment Error.fs7 Bytes.fs7 tcp.fs7 Algorithms.fs7 RSA.fs7 HASH.fs7 HMAC.fs7 Certificate.fs7 CipherSuites.fs7 formats.fs7 TLSInfo.fs7 MAC.fs7 FragCommon.fs7 DataStream.fs7 HandshakePlain.fs7 AlertPlain.fs7 AppDataStream.fs7 TLSFragment.fs7 TLSFragment.fs | tee TLSFragment.tc7

StatefulPlain.tc7: $(libperv) $(libfs7) Error.fs7 Bytes.fs7 tcp.fs7 Algorithms.fs7 RSA.fs7 HASH.fs7 HMAC.fs7 Certificate.fs7 CipherSuites.fs7 formats.fs7 TLSInfo.fs7 MAC.fs7 FragCommon.fs7 DataStream.fs7 HandshakePlain.fs7 AlertPlain.fs7 AppDataStream.fs7 TLSFragment.fs7 StatefulPlain.fs7 StatefulPlain.fs
	 $(f7t) -scripts StatefulPlain Error.fs7 Bytes.fs7 tcp.fs7 Algorithms.fs7 RSA.fs7 HASH.fs7 HMAC.fs7 Certificate.fs7 CipherSuites.fs7 formats.fs7 TLSInfo.fs7 MAC.fs7 FragCommon.fs7 DataStream.fs7 HandshakePlain.fs7 AlertPlain.fs7 AppDataStream.fs7 TLSFragment.fs7 StatefulPlain.fs7 StatefulPlain.fs | tee StatefulPlain.tc7

AEADPlain.tc7: $(libperv) $(libfs7) Error.fs7 Bytes.fs7 tcp.fs7 Algorithms.fs7 RSA.fs7 HASH.fs7 HMAC.fs7 Certificate.fs7 CipherSuites.fs7 formats.fs7 TLSInfo.fs7 MAC.fs7 FragCommon.fs7 DataStream.fs7 HandshakePlain.fs7 AlertPlain.fs7 AppDataStream.fs7 TLSFragment.fs7 StatefulPlain.fs7 AEADPlain.fs7 AEADPlain.fs
	 $(f7t) -scripts AEADPlain Error.fs7 Bytes.fs7 tcp.fs7 Algorithms.fs7 RSA.fs7 HASH.fs7 HMAC.fs7 Certificate.fs7 CipherSuites.fs7 formats.fs7 TLSInfo.fs7 MAC.fs7 FragCommon.fs7 DataStream.fs7 HandshakePlain.fs7 AlertPlain.fs7 AppDataStream.fs7 TLSFragment.fs7 StatefulPlain.fs7 AEADPlain.fs7 AEADPlain.fs | tee AEADPlain.tc7

AEPlain.tc7: $(libperv) $(libfs7) Error.fs7 Bytes.fs7 tcp.fs7 Algorithms.fs7 RSA.fs7 HASH.fs7 HMAC.fs7 Certificate.fs7 CipherSuites.fs7 formats.fs7 TLSInfo.fs7 MAC.fs7 FragCommon.fs7 DataStream.fs7 HandshakePlain.fs7 AlertPlain.fs7 AppDataStream.fs7 TLSFragment.fs7 StatefulPlain.fs7 AEADPlain.fs7 AEPlain.fs7 AEPlain.fs
	 $(f7t) -scripts AEPlain Error.fs7 Bytes.fs7 tcp.fs7 Algorithms.fs7 RSA.fs7 HASH.fs7 HMAC.fs7 Certificate.fs7 CipherSuites.fs7 formats.fs7 TLSInfo.fs7 MAC.fs7 FragCommon.fs7 DataStream.fs7 HandshakePlain.fs7 AlertPlain.fs7 AppDataStream.fs7 TLSFragment.fs7 StatefulPlain.fs7 AEADPlain.fs7 AEPlain.fs7 AEPlain.fs | tee AEPlain.tc7

ENC.tc7: $(libperv) $(libfs7) Error.fs7 Bytes.fs7 tcp.fs7 Algorithms.fs7 RSA.fs7 HASH.fs7 HMAC.fs7 Certificate.fs7 CipherSuites.fs7 formats.fs7 TLSInfo.fs7 MAC.fs7 FragCommon.fs7 DataStream.fs7 HandshakePlain.fs7 AlertPlain.fs7 AppDataStream.fs7 TLSFragment.fs7 StatefulPlain.fs7 AEADPlain.fs7 AEPlain.fs7 ENC.fs7 ENC.fs
	 $(f7t) -scripts ENC Error.fs7 Bytes.fs7 tcp.fs7 Algorithms.fs7 RSA.fs7 HASH.fs7 HMAC.fs7 Certificate.fs7 CipherSuites.fs7 formats.fs7 TLSInfo.fs7 MAC.fs7 FragCommon.fs7 DataStream.fs7 HandshakePlain.fs7 AlertPlain.fs7 AppDataStream.fs7 TLSFragment.fs7 StatefulPlain.fs7 AEADPlain.fs7 AEPlain.fs7 ENC.fs7 ENC.fs | tee ENC.tc7

AEAD.tc7: $(libperv) $(libfs7) Error.fs7 Bytes.fs7 tcp.fs7 Algorithms.fs7 RSA.fs7 HASH.fs7 HMAC.fs7 Certificate.fs7 CipherSuites.fs7 formats.fs7 TLSInfo.fs7 MAC.fs7 FragCommon.fs7 DataStream.fs7 HandshakePlain.fs7 AlertPlain.fs7 AppDataStream.fs7 TLSFragment.fs7 StatefulPlain.fs7 AEADPlain.fs7 AEPlain.fs7 ENC.fs7 AEAD.fs7 AEAD.fs
	 $(f7t) -scripts AEAD Error.fs7 Bytes.fs7 tcp.fs7 Algorithms.fs7 RSA.fs7 HASH.fs7 HMAC.fs7 Certificate.fs7 CipherSuites.fs7 formats.fs7 TLSInfo.fs7 MAC.fs7 FragCommon.fs7 DataStream.fs7 HandshakePlain.fs7 AlertPlain.fs7 AppDataStream.fs7 TLSFragment.fs7 StatefulPlain.fs7 AEADPlain.fs7 AEPlain.fs7 ENC.fs7 AEAD.fs7 AEAD.fs | tee AEAD.tc7

StatefulAEAD.tc7: $(libperv) $(libfs7) Error.fs7 Bytes.fs7 tcp.fs7 Algorithms.fs7 RSA.fs7 HASH.fs7 HMAC.fs7 Certificate.fs7 CipherSuites.fs7 formats.fs7 TLSInfo.fs7 MAC.fs7 FragCommon.fs7 DataStream.fs7 HandshakePlain.fs7 AlertPlain.fs7 AppDataStream.fs7 TLSFragment.fs7 StatefulPlain.fs7 AEADPlain.fs7 AEPlain.fs7 ENC.fs7 AEAD.fs7 StatefulAEAD.fs7 StatefulAEAD.fs
	 $(f7t) -scripts StatefulAEAD Error.fs7 Bytes.fs7 tcp.fs7 Algorithms.fs7 RSA.fs7 HASH.fs7 HMAC.fs7 Certificate.fs7 CipherSuites.fs7 formats.fs7 TLSInfo.fs7 MAC.fs7 FragCommon.fs7 DataStream.fs7 HandshakePlain.fs7 AlertPlain.fs7 AppDataStream.fs7 TLSFragment.fs7 StatefulPlain.fs7 AEADPlain.fs7 AEPlain.fs7 ENC.fs7 AEAD.fs7 StatefulAEAD.fs7 StatefulAEAD.fs | tee StatefulAEAD.tc7

record.tc7: $(libperv) $(libfs7) Error.fs7 Bytes.fs7 tcp.fs7 Algorithms.fs7 RSA.fs7 HASH.fs7 HMAC.fs7 Certificate.fs7 CipherSuites.fs7 formats.fs7 TLSInfo.fs7 MAC.fs7 FragCommon.fs7 DataStream.fs7 HandshakePlain.fs7 AlertPlain.fs7 AppDataStream.fs7 TLSFragment.fs7 StatefulPlain.fs7 AEADPlain.fs7 AEPlain.fs7 ENC.fs7 AEAD.fs7 StatefulAEAD.fs7 record.fs7 record.fs
	 $(f7t) -scripts record Error.fs7 Bytes.fs7 tcp.fs7 Algorithms.fs7 RSA.fs7 HASH.fs7 HMAC.fs7 Certificate.fs7 CipherSuites.fs7 formats.fs7 TLSInfo.fs7 MAC.fs7 FragCommon.fs7 DataStream.fs7 HandshakePlain.fs7 AlertPlain.fs7 AppDataStream.fs7 TLSFragment.fs7 StatefulPlain.fs7 AEADPlain.fs7 AEPlain.fs7 ENC.fs7 AEAD.fs7 StatefulAEAD.fs7 record.fs7 record.fs | tee record.tc7

Alert.tc7: $(libperv) $(libfs7) Error.fs7 Bytes.fs7 tcp.fs7 Algorithms.fs7 RSA.fs7 HASH.fs7 HMAC.fs7 Certificate.fs7 CipherSuites.fs7 formats.fs7 TLSInfo.fs7 MAC.fs7 FragCommon.fs7 DataStream.fs7 HandshakePlain.fs7 AlertPlain.fs7 AppDataStream.fs7 TLSFragment.fs7 StatefulPlain.fs7 AEADPlain.fs7 AEPlain.fs7 ENC.fs7 AEAD.fs7 StatefulAEAD.fs7 record.fs7 Alert.fs7 Alert.fs
	 $(f7t) -scripts Alert Error.fs7 Bytes.fs7 tcp.fs7 Algorithms.fs7 RSA.fs7 HASH.fs7 HMAC.fs7 Certificate.fs7 CipherSuites.fs7 formats.fs7 TLSInfo.fs7 MAC.fs7 FragCommon.fs7 DataStream.fs7 HandshakePlain.fs7 AlertPlain.fs7 AppDataStream.fs7 TLSFragment.fs7 StatefulPlain.fs7 AEADPlain.fs7 AEPlain.fs7 ENC.fs7 AEAD.fs7 StatefulAEAD.fs7 record.fs7 Alert.fs7 Alert.fs | tee Alert.tc7

PRFs.tc7: $(libperv) $(libfs7) Error.fs7 Bytes.fs7 tcp.fs7 Algorithms.fs7 RSA.fs7 HASH.fs7 HMAC.fs7 Certificate.fs7 CipherSuites.fs7 formats.fs7 TLSInfo.fs7 MAC.fs7 FragCommon.fs7 DataStream.fs7 HandshakePlain.fs7 AlertPlain.fs7 AppDataStream.fs7 TLSFragment.fs7 StatefulPlain.fs7 AEADPlain.fs7 AEPlain.fs7 ENC.fs7 AEAD.fs7 StatefulAEAD.fs7 record.fs7 Alert.fs7 PRFs.fs7 PRFs.fs
	 $(f7t) -scripts PRFs Error.fs7 Bytes.fs7 tcp.fs7 Algorithms.fs7 RSA.fs7 HASH.fs7 HMAC.fs7 Certificate.fs7 CipherSuites.fs7 formats.fs7 TLSInfo.fs7 MAC.fs7 FragCommon.fs7 DataStream.fs7 HandshakePlain.fs7 AlertPlain.fs7 AppDataStream.fs7 TLSFragment.fs7 StatefulPlain.fs7 AEADPlain.fs7 AEPlain.fs7 ENC.fs7 AEAD.fs7 StatefulAEAD.fs7 record.fs7 Alert.fs7 PRFs.fs7 PRFs.fs | tee PRFs.tc7

SessionDB.tc7: $(libperv) $(libfs7) Error.fs7 Bytes.fs7 tcp.fs7 Algorithms.fs7 RSA.fs7 HASH.fs7 HMAC.fs7 Certificate.fs7 CipherSuites.fs7 formats.fs7 TLSInfo.fs7 MAC.fs7 FragCommon.fs7 DataStream.fs7 HandshakePlain.fs7 AlertPlain.fs7 AppDataStream.fs7 TLSFragment.fs7 StatefulPlain.fs7 AEADPlain.fs7 AEPlain.fs7 ENC.fs7 AEAD.fs7 StatefulAEAD.fs7 record.fs7 Alert.fs7 PRFs.fs7 SessionDB.fs7 SessionDB.fs
	 $(f7t) -scripts SessionDB Error.fs7 Bytes.fs7 tcp.fs7 Algorithms.fs7 RSA.fs7 HASH.fs7 HMAC.fs7 Certificate.fs7 CipherSuites.fs7 formats.fs7 TLSInfo.fs7 MAC.fs7 FragCommon.fs7 DataStream.fs7 HandshakePlain.fs7 AlertPlain.fs7 AppDataStream.fs7 TLSFragment.fs7 StatefulPlain.fs7 AEADPlain.fs7 AEPlain.fs7 ENC.fs7 AEAD.fs7 StatefulAEAD.fs7 record.fs7 Alert.fs7 PRFs.fs7 SessionDB.fs7 SessionDB.fs | tee SessionDB.tc7

Handshake.tc7: $(libperv) $(libfs7) Error.fs7 Bytes.fs7 tcp.fs7 Algorithms.fs7 RSA.fs7 HASH.fs7 HMAC.fs7 Certificate.fs7 CipherSuites.fs7 formats.fs7 TLSInfo.fs7 MAC.fs7 FragCommon.fs7 DataStream.fs7 HandshakePlain.fs7 AlertPlain.fs7 AppDataStream.fs7 TLSFragment.fs7 StatefulPlain.fs7 AEADPlain.fs7 AEPlain.fs7 ENC.fs7 AEAD.fs7 StatefulAEAD.fs7 record.fs7 Alert.fs7 PRFs.fs7 SessionDB.fs7 Handshake.fs7 Handshake.fs
	 $(f7t) -scripts Handshake Error.fs7 Bytes.fs7 tcp.fs7 Algorithms.fs7 RSA.fs7 HASH.fs7 HMAC.fs7 Certificate.fs7 CipherSuites.fs7 formats.fs7 TLSInfo.fs7 MAC.fs7 FragCommon.fs7 DataStream.fs7 HandshakePlain.fs7 AlertPlain.fs7 AppDataStream.fs7 TLSFragment.fs7 StatefulPlain.fs7 AEADPlain.fs7 AEPlain.fs7 ENC.fs7 AEAD.fs7 StatefulAEAD.fs7 record.fs7 Alert.fs7 PRFs.fs7 SessionDB.fs7 Handshake.fs7 Handshake.fs | tee Handshake.tc7

Dispatch.tc7: $(libperv) $(libfs7) Error.fs7 Bytes.fs7 tcp.fs7 Algorithms.fs7 RSA.fs7 HASH.fs7 HMAC.fs7 Certificate.fs7 CipherSuites.fs7 formats.fs7 TLSInfo.fs7 MAC.fs7 FragCommon.fs7 DataStream.fs7 HandshakePlain.fs7 AlertPlain.fs7 AppDataStream.fs7 TLSFragment.fs7 StatefulPlain.fs7 AEADPlain.fs7 AEPlain.fs7 ENC.fs7 AEAD.fs7 StatefulAEAD.fs7 record.fs7 Alert.fs7 PRFs.fs7 SessionDB.fs7 Handshake.fs7 Dispatch.fs7 Dispatch.fs
	 $(f7t) -scripts Dispatch Error.fs7 Bytes.fs7 tcp.fs7 Algorithms.fs7 RSA.fs7 HASH.fs7 HMAC.fs7 Certificate.fs7 CipherSuites.fs7 formats.fs7 TLSInfo.fs7 MAC.fs7 FragCommon.fs7 DataStream.fs7 HandshakePlain.fs7 AlertPlain.fs7 AppDataStream.fs7 TLSFragment.fs7 StatefulPlain.fs7 AEADPlain.fs7 AEPlain.fs7 ENC.fs7 AEAD.fs7 StatefulAEAD.fs7 record.fs7 Alert.fs7 PRFs.fs7 SessionDB.fs7 Handshake.fs7 Dispatch.fs7 Dispatch.fs | tee Dispatch.tc7

TLS.tc7: $(libperv) $(libfs7) Error.fs7 Bytes.fs7 tcp.fs7 Algorithms.fs7 RSA.fs7 HASH.fs7 HMAC.fs7 Certificate.fs7 CipherSuites.fs7 formats.fs7 TLSInfo.fs7 MAC.fs7 FragCommon.fs7 DataStream.fs7 HandshakePlain.fs7 AlertPlain.fs7 AppDataStream.fs7 TLSFragment.fs7 StatefulPlain.fs7 AEADPlain.fs7 AEPlain.fs7 ENC.fs7 AEAD.fs7 StatefulAEAD.fs7 record.fs7 Alert.fs7 PRFs.fs7 SessionDB.fs7 Handshake.fs7 Dispatch.fs7 TLS.fs7 TLS.fs
	 $(f7t) -scripts TLS Error.fs7 Bytes.fs7 tcp.fs7 Algorithms.fs7 RSA.fs7 HASH.fs7 HMAC.fs7 Certificate.fs7 CipherSuites.fs7 formats.fs7 TLSInfo.fs7 MAC.fs7 FragCommon.fs7 DataStream.fs7 HandshakePlain.fs7 AlertPlain.fs7 AppDataStream.fs7 TLSFragment.fs7 StatefulPlain.fs7 AEADPlain.fs7 AEPlain.fs7 ENC.fs7 AEAD.fs7 StatefulAEAD.fs7 record.fs7 Alert.fs7 PRFs.fs7 SessionDB.fs7 Handshake.fs7 Dispatch.fs7 TLS.fs7 TLS.fs | tee TLS.tc7

### END Autogenerated with "genrules"


#CF ? 
autogen.fsi: $(libperv) $(libfs7) $(recordfs7) record.fs
	$(f7) -nofstypecheck -timeout 300 --define f7 -genfsi -fsifile autogen.fsi -genprotofs -protofsfile autogen.fs -nokindcheck $(lperv) $(libfs7) $(recordfs7) record.fs 

clean:
	@rm -f .tmp *.exe *.pdb *.dll *.obj *.cm* *.pv *.res *~ *.html *.smp *.tc7 *.vo *.glob libcoq.v
