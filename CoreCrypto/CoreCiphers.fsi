module CoreCiphers

type key = byte array
type iv  = byte array

val aes_cbc_encrypt : key -> iv -> byte array -> byte array
val aes_cbc_decrypt : key -> iv -> byte array -> byte array

val des3_cbc_encrypt : key -> iv -> byte array -> byte array
val des3_cbc_decrypt : key -> iv -> byte array -> byte array

type rc4engine

val rc4create  : key -> rc4engine
val rc4process : rc4engine -> byte array -> byte array
