module TLSPlain

open TLSInfo
open Data

type Lengths (* abstractly, a list of desired ciphertext lengths *)

val estimateLengths: KeyInfo -> int -> Lengths

(* Secret App Data *)
type appdata
val appdata: KeyInfo -> Lengths -> bytes -> appdata

type fragment

val concat_fragment_appdata: KeyInfo -> int -> fragment -> Lengths -> appdata -> appdata

val app_fragment: KeyInfo -> Lengths -> appdata ->  ((int * fragment) * (Lengths * appdata))

val pub_fragment: KeyInfo -> bytes -> ((int * fragment) * bytes) 
(* Note that n is *not* the length of the plaintext, it is the length of the target ciphertext *)

type mac

type mac_plain
type add_data = bytes

val ad_fragment: KeyInfo -> add_data -> fragment -> mac_plain

type plain

val concat_fragment_mac_pad: KeyInfo -> int -> fragment -> mac -> plain (* plain includes padding *)

val split_mac: KeyInfo -> int -> plain -> (bool * (fragment * mac))

(* Only for MACOnlyCipherSuites *)
val fragment_mac_to_cipher: KeyInfo -> int -> fragment -> mac -> bytes
val cipher_to_fragment_mac: KeyInfo -> int -> bytes -> (fragment * mac)
(* Only for NullCipherSuites *)
val fragment_to_cipher: KeyInfo -> int -> fragment -> bytes
val cipher_to_fragment: KeyInfo -> int -> bytes -> fragment

(* Only to be used by trusted crypto libraries MAC, ENC *)
val mac_plain_to_bytes: mac_plain -> bytes
val mac_to_bytes: mac -> bytes
val bytes_to_mac: bytes -> mac
val plain_to_bytes: plain -> bytes
val bytes_to_plain: bytes -> plain