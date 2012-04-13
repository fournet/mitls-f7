module Fragment
open TLSInfo
open DataStream

type fragment
val fragment: KeyInfo -> stream -> range -> delta -> fragment * stream
val delta: KeyInfo -> stream -> range -> fragment -> delta * stream
