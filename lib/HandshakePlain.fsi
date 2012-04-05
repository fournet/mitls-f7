module HandshakePlain

open TLSInfo
open Bytes
open DataStream

// protocol-specific abstract fragment,
// and associated functions (never to be called with ideal functionality)
// pretend this is abstract
type stream = DataStream.stream
type fragment = delta

val repr: KeyInfo -> stream -> range -> fragment -> bytes
val fragment: KeyInfo -> stream -> range -> bytes -> fragment
// pretend this is abstract
type ccsFragment = delta
val ccsRepr: KeyInfo -> stream -> range -> ccsFragment -> bytes
val ccsFragment: KeyInfo -> stream -> range -> bytes -> ccsFragment

// FIXME: Port them to DataStream.
// This is the function used by the app to create its own deltas.
val makeFragment: KeyInfo -> bytes -> (DataStream.range * fragment) * bytes
val makeCCSFragment: KeyInfo -> bytes -> (DataStream.range * ccsFragment) * bytes