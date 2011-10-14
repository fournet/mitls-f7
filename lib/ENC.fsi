module ENC

open Data
open TLSInfo
open Error_handling

type symKey = bytes
type plain = bytes
type iv = bytes option
type cipher = bytes

val ENC: KeyInfo -> symKey -> iv -> plain -> cipher Result
val DEC: KeyInfo -> symKey -> iv -> cipher -> plain Result

#if f7
type (;ki:KeyInfo) symKey
type (;ki:KeyInfo) plain
type (;ki:KeyInfo) iv
type (;ki:KeyInfo) cipher

val ENC: ki:KeyInfo -> (;ki) symKey -> (;ki) iv -> (;ki) plain -> ((;ki) cipher) Result
val DEC: ki:KeyInfo -> (;ki) symKey -> (;ki) iv -> (;ki) cipher -> ((;ki) plain) Result
#endif