module MAC

open Data
open Error_handling
open TLSInfo
open TLSPlain

val MAC: KeyInfo -> HMAC.macKey -> mac_plain -> mac Result
val VERIFY: KeyInfo -> HMAC.macKey -> mac_plain -> mac -> unit Result
