miTLS
=====

This is a temporary public repository of miTLS,
a verified reference implementation of the TLS security protocol.

1. Compilation
--------------

To compile, usually running "make" from the top level directory is
enough. (See below for prerequisites.)

The produced executables are placed in the `bin' directory.

Each command line tool accepts a "--help" option that shows all the
available command line options and their default values.

The following make targets are available:

- build (default)
    compiles source code and puts executables in then bin directory

- build-debug
	compiles source code in debug mode

- dist
    prepares a compressed archive that can be distributed

- dist-check
    as dist, but also performs some sanity checks

- clean
    remove object files

- dist-clean
    remove object files and distribution archives

The test suite is currently not released, and thus not
available as a make target.

2. Verification
---------------

Refinement type checking of the code base is driven by the Makefile in
./lib; this file has a "tc7" target for each file to be type checked.
Type checking requires F7 and Z3. Note that the latest version of F7
we use is currently not released.

Each F# implementation file (with .fs extension) may use compilation
flags to control what is passed to F7 vs F#

- ideal: enables ideal cryptographic functionalities in the code.
  (e.g. the ones performing table lookups)

- verify: enables assumptions of events in the code.

Both compilation flags are disabled when compiling the concrete code,
and enabled during type checking.

3. Prerequisites
----------------

In the following, the prerequisites for each supported platform are
given. In general, you need a running F# installation, see
http://fsharp.org/ on how to get the most recent version of F#
for your platform.

### 3.a. Microsoft Windows

Either
- Visual Studio 2013

or
- Cygwin, with the make utility installed
- .NET version 4.5 or above
- Visual F# 3.1 or above

### 3.b. Linux, Mac OS X and other Un*ces

- Mono framework, version 3.4.0 or above; this includes F# 3.1.

