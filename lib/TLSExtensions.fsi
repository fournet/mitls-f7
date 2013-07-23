module TLSExtensions

open Bytes
open Error
open TLSError
open TLSConstants
open TLSInfo

type extensionType

val extensionsBytes: config -> bytes -> bool -> bytes
val parseExtensions: bytes -> (extensionType * bytes) list Result
val inspect_ServerHello_extensions: config -> (extensionType * bytes) list -> bytes -> bool Result
val inspect_ClientHello_extensions: config -> (extensionType * bytes) list -> TLSConstants.cipherSuites -> bytes -> bool Result

val sigHashAlgBytes: Sig.alg -> bytes
val parseSigHashAlg: bytes -> Sig.alg Result
val sigHashAlgListBytes: Sig.alg list -> bytes
val parseSigHashAlgList: bytes -> Sig.alg list Result
val default_sigHashAlg: ProtocolVersion -> cipherSuite -> Sig.alg list
val sigHashAlg_contains: Sig.alg list -> Sig.alg -> bool
val cert_type_list_to_SigHashAlg: certType list -> ProtocolVersion -> Sig.alg list
val cert_type_list_to_SigAlg: certType list -> sigAlg list
val sigHashAlg_bySigList: Sig.alg list -> sigAlg list -> Sig.alg list