module DB

type db

exception DBError of string

val serialize<'T> : 'T -> byte[]
val deserialize<'T> : byte[] -> 'T

val opendb  : string -> db
val closedb : db -> unit
val attach  : db -> string -> string -> db
val put     : db -> byte[] -> byte[] -> unit
val get     : db -> byte[] -> byte[] option
val remove  : db -> byte[] -> bool
val all     : db -> (byte[] * byte[]) list
val keys    : db -> byte[] list
val merge   : db -> string -> unit
val tx      : db -> (db -> 'a) -> 'a
