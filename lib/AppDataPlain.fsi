module AppDataPlain

open TLSInfo

// Application data (the full stream).
// This abstract type must be implemented by the top level application using TLS.
// Keeping it abstract allows us proving that our AppData module behavior
// does not depend on the appdata
type appdata
type lengths = int list

// Interface to the AppData module
val length: SessionInfo -> appdata -> int
val estimateLengths: SessionInfo -> int -> lengths
val empty_appdata: SessionInfo -> appdata
val is_empty_appdata: SessionInfo -> appdata -> bool

// Constructors/Desctructors for appdata.
// They should only be invoked by the top level application.
// Right now, we invoke them from the top TLS module. But we could remove them from there,
// make TLS use the appdata type, and for instance invoke them from TLStream, which is
// already part of the top level application.
val appdata: SessionInfo -> lengths -> Bytes.bytes -> appdata
val appdataBytes: SessionInfo -> appdata -> Bytes.bytes

// A fragment of appdata
type fragment

(* Append the given fragment at the *bottom* of the current appdata *)
val concat_fragment_appdata: KeyInfo -> int -> fragment -> lengths -> appdata -> (lengths * appdata)

(* Exctract the *first* fragment from the *beginning* of appdata *)
val app_fragment: KeyInfo -> lengths -> appdata ->  ((int * fragment) * (lengths * appdata))

// The next should not be invoked when using ideal functionality
val repr: KeyInfo -> int -> fragment -> Bytes.bytes
val fragment: KeyInfo -> int -> Bytes.bytes -> fragment