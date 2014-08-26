#light "off"

module TLSExtensions

open Bytes
open Error
open TLSError
open TLSConstants
open TLSInfo

// Following types only used in handshake
type clientExtension
type serverExtension

// Client side
val prepareClientExtensions: config -> ConnectionInfo -> cVerifyData -> option<sessionHash> -> list<clientExtension>
val clientExtensionsBytes: list<clientExtension> -> bytes
val parseServerExtensions: bytes -> Result<(list<serverExtension>)>
val negotiateClientExtensions: list<clientExtension> -> list<serverExtension> -> bool -> cipherSuite -> Result<negotiatedExtensions>

// Server side
val parseClientExtensions: bytes -> cipherSuites -> Result<(list<clientExtension>)>
val negotiateServerExtensions: list<clientExtension> -> config -> cipherSuite -> (cVerifyData * sVerifyData) -> option<sessionHash> -> (list<serverExtension> * negotiatedExtensions)
val serverExtensionsBytes: list<serverExtension> -> bytes

// Extension-specific
val checkClientRenegotiationInfoExtension: config -> list<clientExtension> -> cVerifyData -> bool
val checkServerRenegotiationInfoExtension: config -> list<serverExtension> -> cVerifyData -> sVerifyData -> bool
val checkClientResumptionInfoExtension:    config -> list<clientExtension> -> sessionHash -> option<bool>
val checkServerResumptionInfoExtension:    config -> list<serverExtension> -> sessionHash -> bool

val hasExtendedMS: negotiatedExtensions -> bool
val hasExtendedPadding: id -> bool

// type extensionType
//
// val extensionsBytes: bool -> bytes -> bytes
// val parseExtensions: bytes -> Result<list<(extensionType * bytes)>>
// val inspect_ServerHello_extensions: list<(extensionType * bytes)> -> bytes -> Result<unit>
// val checkClientRenegotiationInfoExtension: list<(extensionType * bytes)> -> TLSConstants.cipherSuites -> bytes -> bool

//CF what are those doing here? relocate? 
//AP Partially relocate to TLSConstants, partially implement the mandatory signature extension, and embed them there. Maybe TODO before v1.0?
val sigHashAlgBytes: Sig.alg -> bytes
val parseSigHashAlg: bytes -> Result<Sig.alg>
val sigHashAlgListBytes: list<Sig.alg> -> bytes
val parseSigHashAlgList: bytes -> Result<list<Sig.alg>>
val default_sigHashAlg: ProtocolVersion -> cipherSuite -> list<Sig.alg>
val sigHashAlg_contains: list<Sig.alg> -> Sig.alg -> bool
val cert_type_list_to_SigHashAlg: list<certType> -> ProtocolVersion -> list<Sig.alg>
val cert_type_list_to_SigAlg: list<certType> -> list<sigAlg>
val sigHashAlg_bySigList: list<Sig.alg> -> list<sigAlg> -> list<Sig.alg>
