module TLSFragment

open Bytes
open TLSInfo
open TLSConstants

type prehistory
type history = prehistory

type fragment //=
//    | FHandshake of HSFragment.fragment
//    | FCCS of HSFragment.fragment
//    | FAlert of HSFragment.fragment
//    | FAppData of AppFragment.fragment

val emptyHistory: epoch -> history
val addToHistory: epoch -> ContentType -> history -> range -> fragment -> history

//val historyStream: epoch -> ContentType -> history -> stream

val fragmentPlain: epoch -> ContentType -> history -> range -> bytes -> fragment
val fragmentRepr:     epoch -> ContentType -> history -> range -> fragment -> bytes


//val contents:  epoch -> ContentType -> history -> range -> fragment -> Fragment.fragment
//val construct: epoch -> ContentType -> history -> range -> Fragment.fragment -> fragment

val HSFragmentToTLSFragment     : epoch -> history -> range -> HSFragment.fragment -> fragment
val TLSFragmentToHSFragment     : epoch -> history -> range -> fragment -> HSFragment.fragment
val CCSFragmentToTLSFragment    : epoch -> history -> range -> HSFragment.fragment -> fragment
val TLSFragmentToCCSFragment    : epoch -> history -> range -> fragment -> HSFragment.fragment
val AlertFragmentToTLSFragment  : epoch -> history -> range -> HSFragment.fragment -> fragment
val TLSFragmentToAlertFragment  : epoch -> history -> range -> fragment -> HSFragment.fragment
val AppFragmentToTLSFragment    : epoch -> history -> range -> AppFragment.fragment -> fragment
val TLSFragmentToAppFragment    : epoch -> history -> range -> fragment -> AppFragment.fragment