module HSK

open Bytes

type hint = string
type cert = bytes

type pkey

val RSA_pkey: hint -> (cert * pkey) option
