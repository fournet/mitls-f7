module CoreDH

open Bytes

(* ------------------------------------------------------------------------ *)
open System
open System.IO
open System.Text

open Org.BouncyCastle.Math
open Org.BouncyCastle.Security
open Org.BouncyCastle.Crypto.Generators
open Org.BouncyCastle.Crypto.Parameters
open Org.BouncyCastle.Utilities.IO.Pem
open Org.BouncyCastle.Asn1

(* ------------------------------------------------------------------------ *)
open CoreKeys

type skey = dhskey
type pkey = dhpkey

(* ------------------------------------------------------------------------ *)
//SZ This generates parameters with a safe prime p and a randomly chosen g
//SZ There is an efficiency gain in using small g, and OpenSSL uses g = 2 or 5
let gen_params () : dhparams =
    let random    = new SecureRandom() in
    let generator = new DHParametersGenerator() in
        generator.Init(1024, 80, random);
        let dhparams = generator.GenerateParameters() in
            { p = abytes (dhparams.P.ToByteArrayUnsigned());
              g = abytes (dhparams.G.ToByteArrayUnsigned());
              q = Some (abytes (dhparams.Q.ToByteArrayUnsigned())); }

(* ------------------------------------------------------------------------ *)
let gen_key (dh : dhparams) : skey * pkey =
    let dhparams = 
        match dh.q with
          None    -> new DHParameters(new BigInteger(1, cbytes dh.p), new BigInteger(1, cbytes dh.g))
        | Some(q) -> new DHParameters(new BigInteger(1, cbytes dh.p), new BigInteger(1, cbytes dh.g), new BigInteger(1, cbytes q))
    in
    let kparams  = new DHKeyGenerationParameters(new SecureRandom(), dhparams) in
    let kgen     = new DHKeyPairGenerator() in
        kgen.Init(kparams);
        let kpair = kgen.GenerateKeyPair() in
        let pkey  = (kpair.Public  :?> DHPublicKeyParameters ) in
        let skey  = (kpair.Private :?> DHPrivateKeyParameters) in
            ((abytes (skey.X.ToByteArrayUnsigned()), dh), (abytes (pkey.Y.ToByteArrayUnsigned()), dh))

(* ------------------------------------------------------------------------ *)
let agreement (dh : dhparams) (x : dhsbytes) (y : dhpbytes) : bytes =
    let x = new BigInteger(1, cbytes x) in
    let y = new BigInteger(1, cbytes y) in
    let p = new BigInteger(1, cbytes dh.p) in
        abytes (y.ModPow(x, p).ToByteArrayUnsigned())

(* ------------------------------------------------------------------------ *)
let PEM_DH_PARAMETERS_HEADER = "DH PARAMETERS"

// OpenSSL-generated 1024-bit modulus
// openssl dhparam -outform PEM -2 1024
// p = 2q+1, g = 2, order(g) = 2q
let default_params = "-----BEGIN DH PARAMETERS-----
MIIBCgKBgQDbGmBO+JPjdwlyfbFya+fYt2WJztweqhlmXf2gUbQU+wp0iJTITV3s
AHJYsGPtqgUy0pQuQOstJ07L7QTLweGf5jFIorpFE2tUe06uOlT/sF2utOo0mPfx
TeU9wO/ReYhRgTI2760oi8BYJC/HYgWv3/jRniS0EkLihqku1OQCWwIBAgKBgG2N
MCd8SfG7hLk+2Lk18+xbssTnbg9VDLMu/tAo2gp9hTpESmQmrvYAOSxYMfbVAplp
ShcgdZaTp2X2gmXg8M/zGKRRXSKJtao9p1cdKn/YLtdadRpMe/im8p7gd+i8xCjA
mRt31pRF4CwSF+OxAtfv/GjPEloJIXFDVJdqcgEt
-----END DH PARAMETERS-----"

// OpenSSL-generated 1024-bit modulus
// openssl dhparam -outform PEM -5 1024
// p = 2q+1, g = 5, order(g) = 2q
let openssl = "-----BEGIN DH PARAMETERS-----
MIIBCgKBgQC/llta3IgfxUZw7d/TLR1Ql8n61Kq9Ia/5y6+sVJPrAaW3koxMuOdk
1Ly9M2Mw5Y8sL5dgKf0wq9I90rit8V6gryWebcljWIMSCky//s/HvWwLQCk0Mlq6
c96o0QB6nD4Fr6IKNlTajJSBf5+k6+/JpnFDkqxCdYykLjcJzM5g6wIBBQKBgF/L
La1uRA/iozh27+mWjqhL5P1qVV6Q1/zl19YqSfWA0tvJRiZcc7JqXl6ZsZhyx5YX
y7AU/phV6R7pXFb4r1BXks825LGsQYkFJl//Z+PetgWgFJoZLV0571RogD1OHwLX
0QUbKm1GSkC/z9J19+TTOKHJViE6xlIXG4TmZzB1
-----END DH PARAMETERS-----"

// OpenSSL-generated 1024-bit modulus (not a safe prime)
// openssl dhparam -dsaparam -outform PEM 1024, converted to our custom format
// p = q*j + 1, q is a 160-bit prime, order(g) = q
let openssl_not_safe = "-----BEGIN DH PARAMETERS-----
MIIBHwKBgQDn8NH67s1WKGiou8QOdd6wX3DN0hAWkFyKrc6u943pYrFqaqVPRtnd
/l5aDJC9QsVe8CnVm48oK4Yk+/Owsc1xEs6gKz5LVItY897xDa12VAAtMofDxHJi
6X+BVuIZxuysW60fpeeDLd/Y0BFw5aAI0K4z08D1kR/yuyRzu62wQwKBgQC31lgI
UtXMD7eVdkjC9/+a5ZPFP9D/SVjkI7E/BZkvz8ESDC57l67IplT+g+twHfadDnXi
IyRbQ1p48KhEun+I9HziTlUft783ijUcX0fDKg7eRl/1ixyx3lAqes8Ag/xSKo66
UKftmjJgsSWfy76wlElxiwNUlEQib7h+TuxmqwIVANPqNA9w7g6THbmMcaS13ZLL
4AIL
-----END DH PARAMETERS-----"

// BouncyCastle-generated 1024-bit modulus
// p = 2q+1, random g, order(g) = q
let old_params = "-----BEGIN DH PARAMETERS-----
MIIBigKBgQCctCTvtt225fYth0f8s/s+3K27xVqzrDf4fvgrmLj7OGSoJlghp6pQ
8nEGD+8jRQWak9JMrz1OlQ00YnaYuHb9QyO92O5ZVoBTXcZ07EUycXCWPmJaXUm2
X9XGm5BGhfncqc354ixfrt/+oi9h1PscSfiJvjC0rAjtfcE5xVHMNwKBgE/5q47Z
JhFd6fQhUYfiVyNuolP6z0FCZKrmLa9C6UgPLVTfEEOiW6KsCFh5uiCNYcINDZnb
lInlgrHXG2tlv4/QNCXmXBQeUBkVM+4EXOl2ZciEvFv2zAlkUig/CUcLGo/OwsJV
c8o7MMjRcCH7fDi4BIAzdEKdDYB7uEqnGJgnAoGATloSd9tu23L7FsOj/ln9n25W
3eKtWdYb/D98FcxcfZwyVBMsENPVKHk4gwf3kaKCzUnpJleep0qGmjE7TFw7fqGR
3ux3LKtAKa7jOnYimTi4Sx8xLS6k2y/q403II0L87lTm/PEWL9dv/1EXsOp9jiT8
RN8YWlYEdr7gnOKo5hs=
-----END DH PARAMETERS-----"

// 1024-bit MODP Group with 160-bit Prime Order Subgroup (RFC 5114)
// p = q*j + 1, q is a 160-bit prime, order(g) = q
let modp_1024 = "-----BEGIN DH PARAMETERS-----
MIIBHwKBgQCxC4+WoIDgHd6S3l6uXVTsUsmfvPsGo8aaap3KUtI7YWBz4oZ1oj0Y
mDjvHi7mUsAT7LSuqQYRIySXXDzUm4O/rMvdfZDEvXCYSI6cIZpzck7/1vrlZEc4
+qMaT/VbzMChUa9fDci0vUW/N982XBpl5oz9p21NpwjfH7K8LkpDcQKBgQCk0cvV
w/00EmdlpELvuZkF+BBN0lisUH/WQGz/FCZtMSZv6h5cQVZLd35pD1UE8hMWAhe0
sBuIal6RVH+eJ0n01/vX07mpLuGQnQ0iY/gKdqaiTAh6CR9THb8KAWm2oorWYqTR
jnOvoy13nVkY0IvIhY9Nzvl8KiSFXm7rIrOy5QIVAPUYqoeBqN8nirpOfWS3y51J
RiNT
-----END DH PARAMETERS-----"

(* ------------------------------------------------------------------------ *)
let save_params (stream : Stream) (dh : dhparams) =
    let writer    = new PemWriter(new StreamWriter(stream)) in
    let derparams = 
        match dh.q with
          None -> 
            new DerSequence([| new DerInteger(new BigInteger(1, cbytes dh.p)) :> Asn1Encodable;
                               new DerInteger(new BigInteger(1, cbytes dh.g)) :> Asn1Encodable |])
            :> Asn1Encodable
        | Some(q) -> 
            new DerSequence([| new DerInteger(new BigInteger(1, cbytes dh.p)) :> Asn1Encodable;
                               new DerInteger(new BigInteger(1, cbytes dh.g)) :> Asn1Encodable;
                               new DerInteger(new BigInteger(1, cbytes q)) :> Asn1Encodable |])
            :> Asn1Encodable
        in
    writer.WriteObject(new PemObject(PEM_DH_PARAMETERS_HEADER, derparams.GetDerEncoded()));
    writer.Writer.Flush()

(* ------------------------------------------------------------------------ *)
let save_params_to_file (file : string) (dh : dhparams) =
    let filestream = new FileStream(file, FileMode.Create, FileAccess.Write) in
    try
        try
            save_params filestream dh
            true
        finally
            filestream.Close()
    with _ ->
        false

(* ------------------------------------------------------------------------ *)
let fromHex (s:string) : bytes =
    abytes (BigInteger(1, Org.BouncyCastle.Utilities.Encoders.Hex.Decode(s)).ToByteArrayUnsigned())

(* ------------------------------------------------------------------------ *)
let load_params (stream : Stream) : dhparams =
    let reader = new PemReader(new StreamReader(stream)) in
    let obj    = reader.ReadPemObject() in

    if obj.Type <> PEM_DH_PARAMETERS_HEADER then
        raise (new SecurityUtilityException());

    let obj = DerSequence.GetInstance(Asn1Object.FromByteArray(obj.Content)) in

    if obj.Count < 2 then
        raise (new SecurityUtilityException());

    { p = abytes (DerInteger.GetInstance(obj.Item(0)).PositiveValue.ToByteArrayUnsigned()) ;
      g = abytes (DerInteger.GetInstance(obj.Item(1)).PositiveValue.ToByteArrayUnsigned()) ;
      q = if obj.Count > 2 then Some (abytes (DerInteger.GetInstance(obj.Item(2)).PositiveValue.ToByteArrayUnsigned())) else None }

(* ------------------------------------------------------------------------ *)
let load_params_from_file (file : string) : dhparams option =
    let filestream = new FileStream(file, FileMode.Open, FileAccess.Read) in
    try
        try
            Some (load_params filestream)
        finally
            filestream.Close()
    with _ -> None

(* ------------------------------------------------------------------------ *)
let load_default_params () =
    try
        load_params (new MemoryStream(Encoding.ASCII.GetBytes(default_params), false))
    with _ ->
        failwith "cannot load default DH parameters"

(* ------------------------------------------------------------------------ *)
let dhDB = DHDB.create "dhparams-db.db"

(* ------------------------------------------------------------------------ *)
let check_params (pbytes:bytes) (gbytes:bytes) =
    let p = new BigInteger(1, cbytes pbytes)
    let g = new BigInteger(1, cbytes gbytes)
    match DHDB.select dhDB pbytes gbytes with 
    | None -> // unknown group  
        // check g in [2,p-2]
        let pm1 = p.Subtract(BigInteger.One)
        if ((g.CompareTo BigInteger.One) > 0) && ((g.CompareTo pm1) < 0) then
            // check if p is a safe prime, i.e. p = 2*q + 1 with prime q
            let q = pm1.Divide(BigInteger.Two)
            if p.IsProbablePrime(80) && q.IsProbablePrime(80) then 
                let qbytes = abytes (q.ToByteArrayUnsigned())
                ignore (DHDB.insert dhDB pbytes gbytes (qbytes, true))
                true
            else
                // Error.unexpected "check_params: group with unknown order"
                false
        else
            // Error.unexpected "check_params: group with small order"
            false    
    | _ -> true // known group
 
let check_element (pbytes:bytes) (gbytes:bytes) (ebytes:bytes) =
    let p   = new BigInteger(1, cbytes pbytes)
    let e   = new BigInteger(1, cbytes ebytes)
    let pm1 = p.Subtract(BigInteger.One)
    // check e in [2,p-2]
    ((e.CompareTo BigInteger.One) > 0) && ((e.CompareTo pm1) < 0) &&
    // check if p is a safe prime or a prime with a known q
    match DHDB.select dhDB pbytes gbytes with 
    | Some(qbytes,true) ->  // known safe prime
        true
    | Some(qbytes,false) -> // known non-safe prime  
        let q = new BigInteger(1, cbytes qbytes)
        let r = e.ModPow(q, p)
        // For OpenSSL-generated parameters order(g) = 2q, so e^q mod p = p-1
        r.Equals(BigInteger.One) || r.Equals(pm1)
    | None -> 
        Error.unexpected "check_element: unknown DH group"
        false
