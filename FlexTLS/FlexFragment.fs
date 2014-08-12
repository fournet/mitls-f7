#light "off"

module FlexFragment

open Error
open FlexTypes



let parseHeader ns =
    match Tcp.read ns 5 with
    | Error x        -> failwith "Tcp.read header 5 bytes failed"
    | Correct header ->
        match Record.parseHeader header with
        | Error x      -> failwith (sprintf "%A" x)
        | Correct(res) -> res
