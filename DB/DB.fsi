module DB

type db

exception DBError of string

val opendb  : string -> db
val closedb : db -> unit
val put     : db -> byte[] -> byte[] -> unit
val get     : db -> byte[] -> byte[] option
val remove  : db -> byte[] -> bool
val all     : db -> (byte[] * byte[]) list
val keys    : db -> byte[] list
val tx      : db -> (db -> 'a) -> 'a
