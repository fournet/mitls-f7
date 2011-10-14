module MAC

open Data
open Error_handling
open TLSInfo

type macKey = bytes
type text = bytes
type mac = bytes

val MAC: KeyInfo -> macKey -> text -> mac Result
val VERIFY: KeyInfo -> macKey -> text -> mac -> unit Result

#if f7
type (;ki:keyInfo) macKey
type (;ki:keyInfo) text
type (;ki:keyInfo) mac

val MAC: ki:KeyInfo -> (;ki) macKey -> (;ki) text -> ((;ki) mac) Result
val VERIFY: ki:KeyInfo -> (;ki) macKey -> (;ki) text -> (;ki) mac -> unit Result
#endif