(* Copyright (C) 2012--2014 Microsoft Research and INRIA *)

#light "off"

module TLSFragment

open Bytes
open TLSInfo
open TLSConstants
open Range
open Error
open TLSError

type history

type fragment
type plain = fragment

val emptyHistory: epoch -> history
val extendHistory: epoch -> ContentType -> history -> range -> fragment -> history

val handshakeHistory: epoch -> history -> HSFragment.stream
val ccsHistory: epoch -> history -> HSFragment.stream
val alertHistory: epoch -> history -> HSFragment.stream

val plain: epoch -> ContentType -> history -> range -> bytes -> plain
val fragment: id -> ContentType -> range -> bytes -> fragment 
val reprFragment: id -> ContentType -> range -> fragment -> bytes
val repr:  epoch -> ContentType -> history -> range -> plain -> bytes

val HSPlainToRecordPlain     : epoch -> history -> range -> HSFragment.plain -> plain
val CCSPlainToRecordPlain    : epoch -> history -> range -> HSFragment.plain -> plain
val AlertPlainToRecordPlain  : epoch -> history -> range -> HSFragment.plain -> plain
val AppPlainToRecordPlain    : epoch -> history -> range -> AppFragment.plain -> plain
val RecordPlainToHSPlain     : epoch -> history -> range -> plain -> HSFragment.plain
val RecordPlainToCCSPlain    : epoch -> history -> range -> plain -> HSFragment.plain
val RecordPlainToAlertPlain  : epoch -> history -> range -> plain -> HSFragment.plain
val RecordPlainToAppPlain    : epoch -> history -> range -> plain -> AppFragment.plain

val makeExtPad:  id -> ContentType -> range -> fragment -> fragment
val parseExtPad: id -> ContentType -> range -> fragment -> Result<fragment>

#if ideal
val widen: id -> ContentType -> range -> fragment -> fragment
#endif
