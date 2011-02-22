include ../../../../Makefile.inc

all: record.dll record-a.dll Dispatch.dll Dispatch-a.dll

lib7=../../../lib/fs7-interfaces/
libperv = $(lib7)pervasives.fs7 $(lib7)tuples.fs7
lperv = -pervasives $(lib7)pervasives.fs7 -tuples $(lib7)tuples.fs7
libfs7 = $(lib7)pi.fs7 $(lib7)formulas.fs7 $(lib7)list.fs7 $(lib7)data.fs7 $(lib7)xml.fs7 $(lib7)prim-crypto.fs7 $(lib7)crypto.fs7 $(lib7)db.fs7 $(lib7)bytearray.fs7 Stream.fs7
recordfs7 = Error.fs7 tcp.fs7 Sessions.fs7 formats.fs7 CryptoTLS.fs7 record.fs7 
recordfsi = Error.fsi tcp.fsi Sessions.fsi formats.fsi CryptoTLS.fsi record.fsi 
recordfs  = Error.fs  tcp.fs  Sessions.fs  formats.fs  CryptoTLS.fs record.fs
recordfs-a = Error.fs  tcp-a.fs  Sessions.fs  formats.fs CryptoTLS.fs record.fs 

tlsfs7 = Alert.fs7 AppData.fs7 HS_ciphersuites.fs7 HS_msg.fs7 Handshake.fs7 Dispatch.fs7
tlsfsi = Alert.fsi AppData.fsi HS_ciphersuites.fsi HS_msg.fsi Handshake.fsi Dispatch.fsi
tlsfs  = Alert.fs AppData.fs HS_ciphersuites.fs HS_msg.fs Handshake.fs Dispatch.fs

clib=../../../lib/concrete-fs/
slib=../../../lib/symbolic/
ilib=../../../lib/interfaces/
lpi= $(ilib)pi.mli $(slib)pi.ml

intfs = $(ilib)formulas.mli $(ilib)data.mli $(ilib)db.mli $(ilib)crypto.mli $(ilib)xml.mli $(ilib)net.mli


libs= $(clib)pi.fs $(intfs) $(clib)formulas.fs $(clib)db.fs $(clib)data.fs $(clib)crypto.fs $(clib)xml.fs $(clib)net.fs $(clib)bytearray.fs Stream.fs
libs-a= $(intfs) $(slib)formulas.ml $(slib)db.ml $(slib)data.ml $(slib)crypto.ml $(slib)xml.ml $(slib)net.ml $(slib)bytearray.ml Stream-a.fs
libs-a-pr= $(lpi) $(slib)formulas.ml $(slib)db.ml $(slib)data.ml $(slib)crypto.ml $(slib)xml.ml $(slib)net.ml $(slib)bytearray.ml Stream-a.fs

libsym-a.dll: $(lpi) $(libs-a) # building DLLs, e.g. for intellisense integration
	$(fsc) $(lpi) $(libs-a) -a -o $@

libsym.dll: $(libs)
	$(fsc) -d concrete $(libs) -a -o libsym.dll

record.dll: libsym.dll $(recordfsi) $(recordfs)
	$(fsc) -d concrete -r $^ -a -o record.dll

Dispatch.dll: libsym.dll record.dll $(tlsfsi) $(tlsfs)
	$(fsc) -r libsym.dll -r record.dll $(tlsfsi) $(tlsfs) -a -o Dispatch.dll

recordsig.fs7: libsym.dll $(recordfsi) $(recordfs-a)
	$(fsc) -r $^ -a --sig:recordsig.fs7 -o recordsig.dll

Dispatchsig.fs7: libsym.dll record-a.dll $(tlsfsi) $(tlsfs)
	$(fsc) -r libsym.dll -r record-a.dll $(tlsfsi) $(tlsfs) -a --sig:Dispatchsig.fs7 -o Dispatchsig.dll

record-a.dll: libsym-a.dll $(recordfsi) $(recordfs-a)
	$(fsc) -r $^ -a -o record-a.dll

Dispatch-a.dll: libsym-a.dll record-a.dll $(tlsfsi) $(tlsfs)
	$(fsc) -r libsym-a.dll -r record-a.dll $(tlsfsi) $(tlsfs) -a -o Dispatch-a.dll


record.tc7: $(libperv) $(libfs7) $(recordfs7) record.fs
	time $(f7) -timeout 200 --define f7 -nokindcheck $(lperv) $(libfs7) $(recordfs7) record.fs -scripts record -genlst | tee  record.tc7 | grep "Failure\|error\|ERROR\|Exception"; echo ""

Sessions.tc7: $(libperv) $(libfs7) $(recordfs7) Sessions.fs
	time $(f7) -timeout 20 --define f7 -nokindcheck $(lperv) $(libfs7) $(recordfs7) Sessions.fs -scripts record -genlst | tee  Sessions.tc7 | grep "Failure\|error\|ERROR\|Exception"; echo ""

formats.tc7: $(libperv) $(libfs7) $(recordfs7) formats.fs
	time $(f7) -timeout 20 --define f7 -nokindcheck $(lperv) $(libfs7) $(recordfs7) formats.fs -scripts record -genlst | tee  formats.tc7 | grep "Failure\|error\|ERROR\|Exception"; echo ""

%.tc7: $(libperv) $(libfs7) $(recordfs7) $(tlsfs7) %.fs
	time $(f7) -timeout 100 --define f7 -nokindcheck $(lperv) $(libfs7) $(recordfs7) $(tlsfs7) $*.fs -scripts $* -genlst | tee  $*.tc7 | grep "Failure\|error\|ERROR\|Exception"; echo ""

clean:
	@rm -f .tmp *.exe *.pdb *.dll *.obj *.cm* *.pv *.res *~ *.html *.smp *.tc7 *.vo *.glob libcoq.v
