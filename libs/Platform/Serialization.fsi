module Serialization

val serialize<'T>   : 'T -> string
val deserialize<'T> : string -> 'T
