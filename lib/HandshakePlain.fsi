module HandshakePlain

open TLSInfo
open Bytes

// protocol-specific abstract fragment,
// and associated functions (never to be called with ideal functionality)
type fragment
type stream

val repr: KeyInfo -> (* stream -> DataStream.range -> *) fragment -> Bytes.bytes // FIXME: align with streams
val fragment: KeyInfo -> stream -> DataStream.range -> Bytes.bytes -> fragment
type ccsFragment
val ccsRepr: KeyInfo -> (* stream -> DataStream.range -> *) ccsFragment -> Bytes.bytes // FIXME: align with streams
val ccsFragment: KeyInfo -> stream -> DataStream.range -> Bytes.bytes -> ccsFragment

val emptyStream: KeyInfo -> stream
val addFragment: KeyInfo -> stream -> DataStream.range -> fragment -> stream
val addCCSFragment: KeyInfo -> stream -> DataStream.range -> ccsFragment -> stream

val makeFragment: KeyInfo -> bytes -> (DataStream.range * fragment) * bytes
val makeCCSFragment: KeyInfo -> bytes -> (DataStream.range * ccsFragment) * bytes