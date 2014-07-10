open Bytes
type key = bytes
type iv  = bytes
type direction = ForEncryption | ForDecryption
type cipher    = AES | DES3
type mode      = CBC of iv
type scipher = RC4

exception CannotLoadProvider of string
exception NoMessageDigest    of string
exception NoBlockCipher      of cipher * mode option
exception NoStreamCipher     of scipher
exception NoHMac             of string


type blockCipher = {
        bc_Name      : string;
        bc_Direction : direction;
        bc_BlockSize : int;
        bc_Process   : bytes -> bytes
    }

(* ------------------------------------------------------------------------ *)


type streamCipher = {
        sc_Name      : string;
        sc_Direction : direction;
        sc_Process   : bytes -> bytes
    }

(* ------------------------------------------------------------------------ *)
type hMac = {
        hm_Name    : string;
        hm_Process : bytes -> bytes
    }

type messageDigest = {
        md_Name   : string;
        md_Digest : bytes -> bytes
    }

(* let _ = fprintfn stderr "Using lib eay version %10x" (OpenSSL.Core.SSLeay());; *)

let blockCipher (d : direction) (c : cipher) (m : mode option) (k : key) = 
    let alg = 
        match c,m with
        | DES3,None          -> Evp.CIPHER.des_ede3
        | DES3,Some (CBC iv) -> Evp.CIPHER.des_ede3_cbc
        | AES,None when String.length k = (256 / 8) -> Evp.CIPHER.aes_256_ecb
        | AES,Some (CBC iv) when String.length k = (256 / 8) -> Evp.CIPHER.aes_256_cbc
        | AES,None when String.length k = (128 / 8) -> Evp.CIPHER.aes_128_ecb
        | AES,Some (CBC iv) when String.length k = (128 / 8) -> Evp.CIPHER.aes_128_cbc
        | _                             -> raise (NoBlockCipher(c,m)) in

    let engine = Evp.CIPHER.create (alg ()) (d = ForEncryption) in
    Evp.CIPHER.set_key engine k;
    (match m with 
        | Some (CBC iv) -> Evp.CIPHER.set_iv engine iv
        | None -> ());
    ({bc_Name="bc undefined name"; 
      bc_Direction=d;
      bc_BlockSize=Evp.CIPHER.block_size engine;
      bc_Process=Evp.CIPHER.process engine})


let typeOfName (name : string) =
      match name with
        "MD5" -> Some (Evp.MD.md5())
      | "SHA1" -> Some (Evp.MD.sha1())
      | "SHA256" -> Some (Evp.MD.sha256())
      | "SHA384" -> Some (Evp.MD.sha384())
      | "SHA512" -> Some (Evp.MD.sha512()) 
      | _ -> None

let messageDigest (name : string) =
            let tn = typeOfName (name) in
            match tn with
            | Some(type_) -> 
                let engine = Evp.MD.create type_ in
                    {md_Name = name;
                     md_Digest = fun b -> Evp.MD.update engine (b); Evp.MD.final engine}
            | None -> raise(NoMessageDigest(name))
               

let streamCipher (d : direction) (c : scipher) (k : key) =
            let type_ =
                match c with
                | RC4 -> Evp.CIPHER.rc4 ()
            in

            try 
                let engine = Evp.CIPHER.create type_ (d = ForEncryption) in
                Evp.CIPHER.set_key engine k;
                ({sc_Name = "RC4";
                  sc_Direction = d;
                  sc_Process = Evp.CIPHER.process engine}) 
            with _ -> raise (NoStreamCipher(c))


let hMac (name : string) (k : key) =
         match typeOfName(name) with
         | Some type_ -> 
           {hm_Name = name;
            hm_Process = fun b -> Evp.HMAC.hmac type_ k b}
         | _ -> raise (NoHMac(name))
