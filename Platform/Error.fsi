module Error

type ('a,'b) OptResult =
    | Error of 'a
    | Correct of 'b

val perror: string -> string -> string -> string
val correct: 'a -> ('b,'a) OptResult
val unexpected: string -> 'a
val unreachable: string -> 'a