module MAC

open Data
open Error_handling
open TLSInfo
open TLSPlain

type macKey

val MAC: KeyInfo -> macKey -> mac_plain -> mac Result
val VERIFY: KeyInfo -> macKey -> mac_plain -> mac -> unit Result
