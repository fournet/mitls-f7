.PHONY = all-def dist-def clean-def $(target)-fsc

all-def: dist-def
 
target-fsc = $(fsc) $(deps) $(src) -o $(target)

dist-def: build
	mkdir $(distname)/$(this)
	cp $(src) $(distname)/$(this)
	cp $(target) $(distname)/$(this)
	cp $(localfiles) $(distname)/$(this)

clean-def:
	rm -rf bin obj .tmp *.exe *.pdb *.dll *.obj *.cm* *.pv *.res *~ *.html *.smp *.tc7 *.vo *.glob libcoq.v