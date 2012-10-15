module EchoServer

type options = {
    ciphersuite : CipherSuites.cipherSuiteName list;
    tlsversion  : CipherSuites.ProtocolVersion;
    servername  : string;
    clientname  : string option;
}

val entry : options -> unit
