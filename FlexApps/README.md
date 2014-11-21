README
======

Additional material for the
36th IEEE Symposium on Security and Privacy,
Submission #309: "A Messy State of the Union: Taming the Composite State Machine of TLS".
Anonymized for peer review.

This is a confidential and anonymized preview release of FlexTLS and the deviant traces of the SmackTLS scenario,
intended for peer review purposes only. A public release of this software will be available by the conference date.

To preserve anonymity, the FlexTLS tool and all support libraries are released in binary form only. The source code of the "FlexApps" command line interface
and of all the scenarios is provided; for convenience these are also provided in binary form for immediate execution.

All executable are .NET, hence they can run natively on Windows, or via Mono on Unix operating systems.

* RUNNING THE TOOL
The command line can run either one compliant TLS full handshake, or a sequence of deviant traces, either in client or server mode.
In our testing, we first ran a compliant handshake to ensure proper communication could be established with the peer;
then we ran the sequence of deviant traces.

Available options are listed with
./FlexApps.exe -h

For example, a full compliant RSA handshake can be run as a client with the following combination of parameters:
./FlexApps.exe -s fh -r c -k rsa --connect server.example.com:443

The SmackTLS scenario runs a sequence of deviant traces. Four sequence types can be run, giving the following parameters.

- Client deviant traces (i.e. to test a server), with no client authentication (server must not request a certificate)

 ./FlexApps.exe -s smacktls -r c --connect server.example.com:443

- Client deviant traces (i.e. to test a server), with client authentication (server must request a certificate)
 
 ./FlexApps.exe -s smacktls -r c --connect server.example.com:443 --client-cert client.example.com

 - Server deviant traces (i.e. to test a client)

Notes: in all SmackTLS cases, the -k option has no effect. In Server deviant traces, the value of the client CN is not considered.

- Trace Interpreter
This mode is a testing facility to evaluate compliance of other implementations regarding the specification. The tool runs only a succession of abnormal handshake traces and returns the exit status of each trace. Those finishing as Failures should be looked at in more depth as they probably report bugs or non compliances in implementations.

- Attacks
Two kinds of attacks are delivered with the tool.
One is a full man-in-the-middle attack reproducing the known EarlyCCS attack.
The second is the newly presented EarlyFinished attack. It is delivered as server side mode that will mimic the server and the attacker all-together.


The compressed folder also contains the source code for the entry point of the program and all the necessary libraries to link it to. A curious user can directly modify the scenarios as he wishes and recompile the executable to run it from the CLI.
To do so run fsc (Windows) or fsharpc (Mono) :
	
	fsc <all necessary source files>.fs -r <all dlls>

In the compressed directory there are two files called default-dh.pem dhparams-db.bin that should always be present inside the current working directory from where the executable is called.