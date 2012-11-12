module TLSExtensions

open Bytes
open Error

type extensionType

val extensionsBytes: bool -> bytes -> bytes
val parseExtensions: bytes -> (extensionType * bytes) list Result
val inspect_ServerHello_extensions: (extensionType * bytes) list -> bytes -> unit Result
val checkClientRenegotiationInfoExtension: (extensionType * bytes) list -> TLSConstants.cipherSuites -> bytes -> bool