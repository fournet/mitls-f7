module CoreCiphers

type direction = ForEncryption | ForDecryption

type engine

val blocksize      : engine -> int
val direction      : engine -> direction
val process_blocks : engine -> byte array -> byte array

type key = byte array
type iv  = byte array

type cipher = AES | DES3
type mode   = CBC of iv

val engine : mode option -> direction -> cipher -> byte array -> engine

val encrypt : mode option -> cipher -> key -> byte array (* plain *) -> byte array
val decrypt : mode option -> cipher -> key -> byte array (* plain *) -> byte array

val aes_cbc_encrypt : key -> iv -> byte array -> byte array
val aes_cbc_decrypt : key -> iv -> byte array -> byte array

val des3_cbc_encrypt : key -> iv -> byte array -> byte array
val des3_cbc_decrypt : key -> iv -> byte array -> byte array

type rc4engine

val rc4create  : key -> rc4engine
val rc4process : rc4engine -> byte array -> byte array
