module TLSFragment

open Bytes
open TLSInfo
open TLSConstants

type history

type fragment
type plain = fragment

val emptyHistory: epoch -> history
val extendHistory: epoch -> ContentType -> history -> range -> fragment -> history

val plain: epoch -> ContentType -> history -> range -> bytes -> plain
val reprFragment: epoch -> ContentType -> range -> fragment -> bytes
val repr:  epoch -> ContentType -> history -> range -> plain -> bytes

val HSPlainToRecordPlain     : epoch -> history -> range -> HSFragment.plain -> plain
val RecordPlainToHSPlain     : epoch -> history -> range -> plain -> HSFragment.plain
val CCSPlainToRecordPlain    : epoch -> history -> range -> HSFragment.plain -> plain
val RecordPlainToCCSPlain    : epoch -> history -> range -> plain -> HSFragment.plain
val AlertPlainToRecordPlain  : epoch -> history -> range -> HSFragment.plain -> plain
val RecordPlainToAlertPlain  : epoch -> history -> range -> plain -> HSFragment.plain
val AppPlainToRecordPlain    : epoch -> history -> range -> AppFragment.plain -> plain
val RecordPlainToAppPlain    : epoch -> history -> range -> plain -> AppFragment.plain