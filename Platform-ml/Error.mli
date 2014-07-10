type ('a,'b) ty_OptResult =
    | Error of 'a
    | Correct of 'b

val perror: string -> string -> string -> string

(*@ val correct: x:'a -> y:('b,'a) OptResult{y = Correct(x)} *)
val correct: 'a -> ('b,'a) ty_OptResult

(* Both unexpected and unreachable are aliases for failwith;
   they indicate code that should never be executed at runtime.
   This is verified by typing only for the unreachable function;
   this matters e.g. when dynamic errors are security-critical *)

(*@ val unexpected: string -> 'a {false} @*)
val unexpected: string -> 'a

(*@ val unreachable: string {false} -> 'a @*)
val unexpected: string -> 'a


