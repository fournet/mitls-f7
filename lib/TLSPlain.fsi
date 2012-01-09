module TLSPlain

open TLSInfo
open Bytes

// AP: new: keep here and do not duplicate
type lengths = int list (* a list of desired ciphertext lengths *)

val estimateLengths: SessionInfo -> int -> lengths

// AP: new: as we see, AppData and "other (public) fragments" were already duplicated here. Just move them
//     to the appropriate places, and remove silly cast functions

(* Secret App Data *)
type appdata
// AP: new: the following function could be in the AppPlain module (the plain module for the Application)
val appdata: SessionInfo -> lengths -> bytes -> appdata
val empty_appdata: SessionInfo -> appdata
val is_empty_appdata: appdata -> bool

type fragment

(* Append the given fragment at the *bottom* of the current appdata *)
val concat_fragment_appdata: SessionInfo -> int -> fragment -> lengths -> appdata -> (lengths * appdata)

(* Exctract the *first* fragment from the *beginning* of appdata *)
val app_fragment: SessionInfo -> lengths -> appdata ->  ((int * fragment) * (lengths * appdata))

// AP: new: move the following to the AppPlain module
(* Only used by appdata module, to return the received concrete bytes to the application *)
val get_bytes: appdata -> bytes 

// AP: new: they should disappear, and get embedded into the representation in each subprotocol
(* Fragmentation and de-fragmentation functions used by non-appdata protocols, that only exchange public data *)
val pub_fragment: SessionInfo -> bytes -> ((int * fragment) * bytes) 
(* Note that n is *not* the length of the plaintext, it is the length of the target ciphertext *)
val pub_fragment_to_bytes: SessionInfo -> int -> fragment -> bytes

// AP: new: this can stay here (and we rename this module).
//     I'd prefer not to create one plain module for each crypto module,
//     as this would bloat the number of modules, and, if we remove the things above, is
//     not too much for a single file.
type mac

type mac_plain
type add_data = bytes

val ad_fragment: KeyInfo -> add_data -> fragment -> mac_plain

type plain

val concat_fragment_mac_pad: KeyInfo -> int -> fragment -> mac -> plain (* plain includes padding *)

val split_mac: KeyInfo -> int -> plain -> (bool * (fragment * mac))

// AP: we still find a way to formally justify the presence of these functions.
(* Only for MACOnlyCipherSuites *)
val fragment_mac_to_cipher: KeyInfo -> int -> fragment -> mac -> bytes
val cipher_to_fragment_mac: KeyInfo -> int -> bytes -> (fragment * mac)
(* Only for NullCipherSuites *)
val fragment_to_cipher: KeyInfo -> int -> fragment -> bytes
val cipher_to_fragment: KeyInfo -> int -> bytes -> fragment

// AP: do we like this, or do we want to talk about?
(* Only to be used by trusted crypto libraries MAC, ENC *)
val mac_plain_to_bytes: mac_plain -> bytes
val mac_to_bytes: mac -> bytes
val bytes_to_mac: bytes -> mac
val plain_to_bytes: plain -> bytes
val bytes_to_plain: bytes -> plain