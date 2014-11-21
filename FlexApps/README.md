README
======

Additional material for the
36th IEEE Symposium on Security and Privacy,
Submission #309: "A Messy State of the Union: Taming the Composite State Machine of TLS".
Anonymized for peer review.

This is a confidential and anonymized preview release of FlexTLS and the
deviant traces of the SmackTLS scenario, intended for peer review purposes
only. A public release of this software will be available by the conference
date.

To preserve anonymity, the FlexTLS tool and all support libraries are released
in binary form only. The source code of the "FlexApps" command line interface
and of all the scenarios is provided; for convenience these are also provided
in binary form for immediate execution.

All executables are .NET, hence they run natively on Windows, and via Mono
on Unix operating systems. Please install the latest Mono version from
http://www.mono-project.com/, as operating system packages have known issues.

* RUNNING THE TOOL
The FlexApps command line tool can run either one compliant TLS full
handshake, or a sequence of deviant traces, either in client or server mode.
In our testing, we first ran a compliant handshake to ensure proper
communication could be established with the peer; then we ran the sequence of
deviant traces.

Available options are listed with
./FlexApps.exe -h

For example, a full compliant RSA handshake can be run as a client with the
following combination of parameters:
./FlexApps.exe -s fh -r c -k rsa --connect server.example.com:443

The SmackTLS scenario runs a sequence of deviant traces. Four sequence types
can be run, by providing the following parameters.

- Client deviant traces (i.e. to test a server), with no client authentication (server must not request a certificate)

 ./FlexApps.exe -s smacktls -r c --connect server.example.com:443

- Client deviant traces (i.e. to test a server), with client authentication (server must request a certificate)
 
 ./FlexApps.exe -s smacktls -r c --connect server.example.com:443 --client-cert client.example.com

- Server deviant traces (i.e. to test a client), with client presenting no certificate, if asked
 ./FlexApps.exe -s smacktls -r s --accept 0.0.0.0:6443 --server-cert server.example.com

- Server deviant traces (i.e. to test a client), with client presenting some certificate, if asked
 ./FlexApps.exe -s smacktls -r s --accept 0.0.0.0:6443 --server-cert server.example.com --client-cert dummy

Note: in all SmackTLS cases, the -k option has no effect. In Server deviant
traces, the value of the --client-cert CN is not considered, instead any
client-provided certificate will be accepted, for testing purposes.

Each SmackTLS scenario produces a log, both on the command line, and in the
logs directory. In such log, a line starting with "INFO --- BEGIN" signals the
beginning of a deviant trace test. A corresponding "INFO --- END SUCCESS" line
means that the deviant trace was correctly rejected by the tested
implementation, while "INFO --- END FAILURE" means that the SmackTLS flagged
the deviant trace, since the peer seems to have accepted it, or generally
misbehaved.

Additionally, two state machine attacks implemented as FlexTLS scenarios are provided with this preview
release.
The first is a full man-in-the-middle attack reproducing the known EarlyCCS attack on OpenSSL <= 1.0.1g.
The second is the newly presented EarlyFinished attack on Java implementations. The attack code runs
as a server, impersonating arbitrary servers to a victim Java client.

* COMPILING THE SOURCE CODE
The source code of the command line interface and of all the scenarios is included in this preview release.
To compile the source code, run:

fsc Parsing.fs Attack_*.fs Handshake_full_*.fs SmackTLS.fs Application.fs -r BouncyCastle.Crypto.dll -r CoreCrypto.dll -r DB.dll -r FlexTLS.dll -r NLog.dll -r OpenSSL.dll -r Platform.dll --mlcompatibility -o MyFlexApps.exe

The F# compiler is usually called fsc on Windows, and fsharpc on Mono-served systems.
	