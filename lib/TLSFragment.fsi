module TLSFragment

open Bytes
open TLSInfo
open TLSConstants
open Range

type history

type fragment
type plain = fragment

val emptyHistory: epoch -> history
val extendHistory: epoch -> ContentType -> history -> range -> fragment -> history

val handshakeHistory: epoch -> history -> HSFragment.stream
val ccsHistory: epoch -> history -> HSFragment.stream
val alertHistory: epoch -> history -> HSFragment.stream

val plain: epoch -> ContentType -> history -> range -> bytes -> plain
val reprFragment: epoch -> ContentType -> range -> fragment -> bytes
val repr:  epoch -> ContentType -> history -> range -> plain -> bytes

val HSPlainToRecordPlain     : epoch -> history -> range -> HSFragment.plain -> plain
val CCSPlainToRecordPlain    : epoch -> history -> range -> HSFragment.plain -> plain
val AlertPlainToRecordPlain  : epoch -> history -> range -> HSFragment.plain -> plain
val AppPlainToRecordPlain    : epoch -> history -> range -> AppFragment.plain -> plain
val RecordPlainToHSPlain     : epoch -> history -> range -> plain -> HSFragment.plain
val RecordPlainToCCSPlain    : epoch -> history -> range -> plain -> HSFragment.plain
val RecordPlainToAlertPlain  : epoch -> history -> range -> plain -> HSFragment.plain
val RecordPlainToAppPlain    : epoch -> history -> range -> plain -> AppFragment.plain

#if ideal
val widen: epoch -> ContentType -> range -> fragment -> fragment
#endif