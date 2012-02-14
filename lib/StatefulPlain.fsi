module StatefulPlain
open TLSInfo
open DataStream

type fragmentSequence
type fragment 

val emptySequence: KeyInfo -> fragmentSequence
val sequenceLength:KeyInfo -> fragmentSequence -> int

val addFragment: KeyInfo -> fragmentSequence -> bytes -> range -> 
                 fragment -> fragmentSequence

val TLSFragmentToFragment: KeyInfo -> range -> int -> TLSFragment.fragment -> fragment
val FragmentToTLSFragment: KeyInfo -> range -> int -> fragment -> TLSFragment.fragment

