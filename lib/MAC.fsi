module MAC

open Data
open Error_handling
open TLSInfo
open HMAC

val MAC: KeyInfo -> macKey -> text -> mac Result
val VERIFY: KeyInfo -> macKey -> text -> mac -> unit Result
