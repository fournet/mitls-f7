module MAC

open Data
open Error_handling
open TLSInfo

type macKey
type mac_plain = bytes
type mac = bytes

val MAC: KeyInfo -> macKey -> mac_plain -> mac Result
val VERIFY: KeyInfo -> macKey -> mac_plain -> mac -> unit Result
