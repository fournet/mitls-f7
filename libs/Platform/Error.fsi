(* Copyright (C) 2012--2014 Microsoft Research and INRIA *)

module Error

type ('a,'b) optResult =
    | Error of 'a
    | Correct of 'b

val perror: string -> string -> string -> string
val correct: 'a -> ('b,'a) optResult
val unexpected: string -> 'a
val unreachable: string -> 'a