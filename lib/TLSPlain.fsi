module TLSPlain

open TLSInfo
open Bytes

type Lengths (* abstractly, a list of desired ciphertext lengths *)

val estimateLengths: SessionInfo -> int -> Lengths

(* Secret App Data *)
type appdata
val appdata: SessionInfo -> Lengths -> bytes -> appdata
val empty_appdata: appdata
val empty_lengths: Lengths
val is_empty_appdata: appdata -> bool

type fragment

(* Append the given fragment at the *bottom* of the current appdata *)
val concat_fragment_appdata: SessionInfo -> int -> fragment -> Lengths -> appdata -> (Lengths * appdata)

(* Exctract the *first* fragment from the *beginning* of appdata *)
val app_fragment: SessionInfo -> Lengths -> appdata ->  ((int * fragment) * (Lengths * appdata))

(* Only used by appdata module, to return the received concrete bytes to the application *)
val get_bytes: appdata -> bytes 

(* Fragmentation and de-fragmentation functions used by non-appdata protocols, that only exchange public data *)
val pub_fragment: SessionInfo -> bytes -> ((int * fragment) * bytes) 
(* Note that n is *not* the length of the plaintext, it is the length of the target ciphertext *)
val pub_fragment_to_bytes: SessionInfo -> int -> fragment -> bytes

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