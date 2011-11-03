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

val ENC: KeyInfo -> symKey -> ivOpt -> plain -> (ivOpt * cipher) Result
val DEC: KeyInfo -> symKey -> ivOpt -> cipher -> (ivOpt * plain) Result
