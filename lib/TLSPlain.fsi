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

type plain

val concat_fragment_mac_pad: KeyInfo -> int -> fragment -> mac -> plain (* plain includes padding *)

val split_mac: KeyInfo -> int -> plain -> (fragment * mac) (* Returns a random fragment if pad checking fails *)
