# We depend on the following:
#
# .NET (crypto) : 3.5 
# FSharp        : 2.0.0.0 or 1.9.6.2
# F7            : compiled 27 July 2009
# + Z3          : 1.2 or 2.0
# FS2PV         : ?
# + ProVerif    : 1.84pl2
# Coq		: 8.2

#The directory that this Makefile.inc lives in
TOP := $(dir $(lastword $(MAKEFILE_LIST)))

#-----------------------------------------
#User-dependent Installation Directories
#-----------------------------------------
raw_arch = $(shell uname) 

ifeq ($(findstring $(raw_arch),WOW64),) # Win32

arch = Win32
FW="C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\"
FSCDIR="/cygdrive/c/Program Files/Microsoft F\#/v4.0/"
FSCCDIR="/cygdrive/c/Program Files/FSharpPowerPack-2.0.0.0/bin/"
FS2PVDIR=$(TOP)bin/
COQDIR="/cygdrive/c/Program Files/Coq/bin/"

else

arch = x64
FW="C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\"
FSCDIR="/cygdrive/c/Program Files (x86)/Microsoft F\#/v4.0/"
FSCCDIR="/cygdrive/c/Program Files (x86)/FSharpPowerPack-2.0.0.0/bin/"
FS2PVDIR=$(TOP)bin/
COQDIR="/cygdrive/c/Program Files \(x86\)/Coq/bin/"

endif



# using the latest versions of F#, with annoyingly conflicting command-line syntaxes

fscexe=$(FSCDIR)fsc.exe
fsccexe=$(FSCDIR)fsc.exe
quiet=--nologo --warn:0 
fscopts=-d fs -g --mlcompatibility -r FSharp.PowerPack.dll -r FSharp.PowerPack.Compatibility.dll $(quiet) -r System.Xml.dll -r System.Security.dll 
fsccopts= --noframework -r $(FW)mscorlib.dll -r $(FW)System.dll -r $(FW)System.Numerics.dll --mlcompatibility -r FSharp.PowerPack.dll -r FSharp.PowerPack.Compatibility.dll  $(quiet) -r $(TOP)bin/FSharp.Compiler.dll 

fsyaccexe=$(FSCCDIR)fsyacc.exe
fslexexe=$(FSCCDIR)fslex.exe
f7exe=$(TOP)bin/f7.exe
z3exe=$(TOP)bin/z3.exe
fs2pvexe=$(FS2PVDIR)fs2pv.exe
goal2genexe =$(FS2PVDIR)goal2gen.exe

fsc = $(fscexe) $(fscopts)
fscc = $(fsccexe) $(fsccopts)
fscomp=$(fsccexe) --mlcompatibility
fsyacc = $(fsyaccexe)
fslex = $(fslexexe)
f7 = $(f7exe) 
z3 = $(z3exe)
fs2pv = $(fs2pvexe) -maxopt
goal2gen = $(goal2genexe)

proverif =$(FS2PVDIR)analyzer.exe
coqc=$(COQDIR)coqc.exe








