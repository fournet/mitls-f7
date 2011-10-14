module ENC

open Data
open TLSInfo
open Error_handling

type symKey = bytes
type plain = bytes
type iv = bytes
type ivOpt =
    | SomeIV of iv
    | NoneIV
type cipher = bytes

val ENC: KeyInfo -> symKey -> ivOpt -> plain -> (iv * cipher) Result
val DEC: KeyInfo -> symKey -> iv -> cipher -> (ivOpt * plain) Result

#if f7
type (;ki:KeyInfo) symKey
type (;ki:KeyInfo) plain

type (;ki:KeyInfo) iv = IVSome of iv{ki.ver = } | IVNone of unit{ki.ver..}


type (;ki:KeyInfo) cipher

val ENC: ki:KeyInfo -> (;ki) symKey -> (;ki) iv -> (;ki) plain -> ((;ki) cipher) Result
val DEC: ki:KeyInfo -> (;ki) symKey -> (;ki) iv -> (;ki) cipher -> ((;ki) plain) Result
#endif