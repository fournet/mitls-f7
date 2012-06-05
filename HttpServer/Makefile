include ../Makefile.inc

localfiles = Makefile
src = Utils.fs Mime.fs HttpLogger.fs HttpCode.fs HttpHeaders.fs HttpData.fs HttpStreamReader.fs HttpServer.fs Program.fs
deps = -r ../lib/TLSlib.dll -r ../TLSharp/TLStream.dll
target = HttpServer.exe

.PHONY: all build dist clean

all: dist

$(target): $(src)
	$(target-fsc)
	
build: $(target)

clean: clean-def

dist: dist-def

include ../Makefile_default.inc