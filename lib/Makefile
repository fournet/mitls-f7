include ../../../../Makefile.inc

#all: record.dll record-a.dll Dispatch.dll Dispatch-a.dll
all: record.dll Dispatch.dll TLS.dll

lib7=../../../lib/fs7-interfaces/
libperv = $(lib7)pervasives.fs7 $(lib7)tuples.fs7
lperv = -pervasives $(lib7)pervasives.fs7 -tuples $(lib7)tuples.fs7
libfs7 = $(lib7)formulas.fs7 $(lib7)pi.fs7 $(lib7)data.fs7 $(lib7)list.fs7 $(lib7)xml.fs7 $(lib7)db.fs7 $(lib7)bytearray.fs7

recordfs7 = Error.fs7 tcp.fs7 OtherCrypto.fsi Principal.fs7 Algorithms.fsi HS_ciphersuites.fs7 formats.fs7 TLSInfo.fsi HASH.fsi HMAC.fsi MAC.fs7 TLSPlain.fs7 ENC.fs7 AEAD.fs7 Stream.fs7 record.fsi
recordfsi = Error.fsi tcp.fsi OtherCrypto.fsi Principal.fsi Algorithms.fsi HS_ciphersuites.fsi formats.fsi TLSInfo.fsi HASH.fsi HMAC.fsi MAC.fsi TLSPlain.fsi ENC.fsi AEAD.fsi Stream.fsi record.fsi
recordfs = Error.fs tcp.fs OtherCrypto.fs Principal.fs Algorithms.fs HS_ciphersuites.fs formats.fs TLSInfo.fs HASH.fs HMAC.fs MAC.fs TLSPlain.fs ENC.fs AEAD.fs Stream.fs record.fs
#recordfs-a = Error.fs  tcp-a.fs  Sessions.fs  formats.fs CryptoTLS.fs record.fs 

# TODO: not yet up-to-date with the new code structure.
dispatchfs7 = AppCommon.fs7 SessionDB.fs7 HS_msg.fs7 Handshake.fs7 AppData.fs7 Alert.fs7 Dispatch.fs7
dispatchfsi = AppCommon.fsi SessionDB.fsi HS_msg.fsi Handshake.fsi AppData.fsi Alert.fsi Dispatch.fsi
dispatchfs = AppCommon.fs SessionDB.fs HS_msg.fs Handshake.fs AppData.fs Alert.fs Dispatch.fs

tlsfs7 = TLS.fs7
tlsfsi = TLS.fsi
tlsfs = TLS.fs

clib=../../../lib/concrete-fs/
slib=../../../lib/symbolic/
ilib=../../../lib/interfaces/
lpi= $(ilib)pi.mli $(slib)pi.ml

intfs = $(ilib)formulas.mli $(ilib)data.mli $(ilib)db.mli $(ilib)crypto.mli $(ilib)xml.mli $(ilib)net.mli


#libs= $(clib)pi.fs $(intfs) $(clib)formulas.fs $(clib)db.fs $(clib)data.fs $(clib)crypto.fs $(clib)xml.fs $(clib)net.fs $(clib)bytearray.fs
libs= $(clib)formulas.fs $(clib)pi.fs $(clib)db.fs $(clib)data.fs $(clib)crypto.fs $(clib)xml.fs $(clib)net.fs $(clib)bytearray.fs
libs-a= $(intfs) $(slib)formulas.ml $(slib)db.ml $(slib)data.ml $(slib)crypto.ml $(slib)xml.ml $(slib)net.ml $(slib)bytearray.ml
libs-a-pr= $(lpi) $(slib)formulas.ml $(slib)db.ml $(slib)data.ml $(slib)crypto.ml $(slib)xml.ml $(slib)net.ml $(slib)bytearray.ml

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



record.tc7: $(libperv) $(libfs7) $(recordfs7) record.fs
	time $(f7) -debug -nofstypecheck -timeout 30 --define f7 -nokindcheck $(lperv) $(libfs7) $(recordfs7) record.fs -scripts record -genlst | tee  record.tc7 | grep "Failure\|error\|ERROR\|Exception"; echo ""

autogen.fsi: $(libperv) $(libfs7) $(recordfs7) record.fs
	time $(f7) -nofstypecheck -timeout 300 --define f7 -genfsi -fsifile autogen.fsi -genprotofs -protofsfile autogen.fs -nokindcheck $(lperv) $(libfs7) $(recordfs7) record.fs 

Sessions.tc7: $(libperv) $(libfs7) $(recordfs7) Sessions.fs
	time $(f7) -timeout 20 --define f7 -nokindcheck $(lperv) $(libfs7) $(recordfs7) Sessions.fs -scripts Sessions -genlst | tee  Sessions.tc7 | grep "Failure\|error\|ERROR\|Exception"; echo ""

formats.tc7: $(libperv) $(libfs7) $(recordfs7) formats.fs
	time $(f7) -timeout 20 --define f7 -nokindcheck $(lperv) $(libfs7) $(recordfs7) formats.fs -scripts formats -genlst | tee  formats.tc7 | grep "Failure\|error\|ERROR\|Exception"; echo ""

AppData.tc7: $(libperv) $(libfs7) $(recordfs7) AppData.fs7 AppData.fs 
	time $(f7) -timeout 200 --define f7 -nokindcheck $(lperv) $(libfs7) $(recordfs7) AppData.fs7 AppData.fs -scripts AppData -genlst | tee AppData.tc7 | grep "Failure\|error\|ERROR\|Exception"; echo ""

%.tc7: $(libperv) $(libfs7) $(recordfs7) $(tlsfs7) %.fs
	time $(f7) -nofstypecheck -timeout 30 --define f7 -nokindcheck $(lperv) $(libfs7) $(recordfs7) $(tlsfs7) $*.fs -scripts $* -genlst | tee  $*.tc7 | grep "Failure\|error\|ERROR\|Exception"; echo ""

clean:
	@rm -f .tmp *.exe *.pdb *.dll *.obj *.cm* *.pv *.res *~ *.html *.smp *.tc7 *.vo *.glob libcoq.v
