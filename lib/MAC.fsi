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
type (;ki:keyInfo) text = bytes
type (;ki:keyInfo) mac = bytes

val MAC: ki:KeyInfo -> (;ki) macKey -> t:(;ki) text{Msg(ki,t)} -> ((;ki) mac) Result
val VERIFY: ki:KeyInfo -> (;ki) macKey -> t:(;ki) text -> (;ki) mac -> 
            unit{CMA(ki) => Msg(ki,t)} Result
#endif