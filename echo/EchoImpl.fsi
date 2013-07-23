module EchoImpl

type options = {
    ciphersuite : TLSConstants.cipherSuiteName list;
    tlsversion  : TLSConstants.ProtocolVersion;
    servername  : string;
    clientname  : string option;
    localaddr   : System.Net.IPEndPoint;
    sessiondir  : string;
    extPad      : bool;
}

val client : options -> unit
val server : options -> unit
