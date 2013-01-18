module CoreCiphers

type direction = ForEncryption | ForDecryption

type engine

exception InvalidBlockSize

val blocksize      : engine -> int
val direction      : engine -> direction
val process_blocks : engine -> byte[] -> byte[]

type key = byte[]
type iv  = byte[]

type cipher = AES | DES3
type mode   = CBC of iv

val engine : mode option -> direction -> cipher -> byte[] -> engine

val encrypt : mode option -> cipher -> key -> byte[] (* plain *) -> byte[]
val decrypt : mode option -> cipher -> key -> byte[] (* plain *) -> byte[]

val aes_cbc_encrypt : key -> iv -> byte[] -> byte[]
val aes_cbc_decrypt : key -> iv -> byte[] -> byte[]

val des3_cbc_encrypt : key -> iv -> byte[] -> byte[]
val des3_cbc_decrypt : key -> iv -> byte[] -> byte[]

type rc4engine

val rc4create  : key -> rc4engine
val rc4process : rc4engine -> byte[] -> byte[]
