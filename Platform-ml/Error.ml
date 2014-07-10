type ('a,'b) ty_OptResult =
    | Error of 'a
    | Correct of 'b

let perror (file:string) (line:string) (text:string) =
    text

let correct x = Correct x

let unexpected info = failwith info
let unreachable info = failwith info