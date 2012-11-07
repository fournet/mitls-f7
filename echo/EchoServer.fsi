module EchoServer

type options = {
    ciphersuite : TLSConstants.cipherSuiteName list;
    tlsversion  : TLSConstants.ProtocolVersion;
    servername  : string;
    clientname  : string option;
    localaddr   : System.Net.IPEndPoint;
}

val entry : options -> unit
