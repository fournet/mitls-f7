module EchoImpl

type options = {
    ciphersuite   : TLSConstants.cipherSuiteName list;
    tlsminversion : TLSConstants.ProtocolVersion;
    tlsmaxversion : TLSConstants.ProtocolVersion;
    servername    : string;
    clientname    : string option;
    localaddr     : System.Net.IPEndPoint;
    sessiondir    : string;
}

val client : options -> unit
val server : options -> unit
