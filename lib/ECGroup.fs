#light "off"

module ECGroup

open Bytes
open CoreKeys
open Error
open TLSError

type ec_curve =
| ECC_P256
| ECC_P384
| ECC_P521
| ECC_EXPLICIT_PRIME
| ECC_EXPLICIT_BINARY
| ECC_UNKNOWN of int

type point_format =
| ECP_UNCOMPRESSED
| ECP_UNKNOWN of int