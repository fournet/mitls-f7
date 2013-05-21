(* ------------------------------------------------------------------------ *)
namespace CSPCryptoProvider

open System
open System.Security.Cryptography

open CryptoProvider

(* ------------------------------------------------------------------------ *)
type CSPMessageDigest (name : string, engine : HashAlgorithm) =
    interface MessageDigest with
        member self.Name =
            name

        member self.Digest (b : byte[]) =
            engine.ComputeHash (b)

(* ------------------------------------------------------------------------ *)
type CSPBlockCipher (name : string, direction : direction, engine : SymmetricAlgorithm) =
    let transform =
        match direction with
        | ForEncryption -> engine.CreateEncryptor ()
        | ForDecryption -> engine.CreateDecryptor ()

    interface IDisposable with
        member self.Dispose () =
            engine.Dispose ()

    interface BlockCipher with
        member self.Name =
            name

        member self.Direction =
            direction

        member self.BlockSize =
            engine.BlockSize

        member self.Process (b : byte[]) =
            match direction with
            | ForEncryption ->
                use memory = new System.IO.MemoryStream () in
                use stream = new CryptoStream (memory, transform, CryptoStreamMode.Write) in
                    stream.Write (b, 0, b.Length);
                    stream.FlushFinalBlock ();
                    memory.ToArray ()

            | ForDecryption ->
                use memory = new System.IO.MemoryStream (b) in
                let stream = new CryptoStream (memory, transform, CryptoStreamMode.Read) in
                let plain  = Array.zeroCreate (b.Length) in  
                    ignore (stream.Read (plain, 0, plain.Length));
                    plain

(* ------------------------------------------------------------------------ *)
type cspmode = ECB | CBC of iv

type CSPProvider () =
    interface Provider with
        (* FIXME: exception ? *)
        member self.MessageDigest (name : string) =
            let name   = name.ToUpperInvariant () in
            let engine = HashAlgorithm.Create (name) in
                Some (new CSPMessageDigest (name, engine) :> MessageDigest)

        member self.BlockCipher (d : direction) (c : cipher) (m : mode option) (k : key) =
            let of_csp_mode m =
                let name, engine =
                    match c with
                    | AES  -> "AES" , new AesCryptoServiceProvider       () :> SymmetricAlgorithm
                    | DES3 -> "3DES", new TripleDESCryptoServiceProvider () :> SymmetricAlgorithm
                in
                    engine.Padding <- PaddingMode.None;
                    engine.KeySize <- 8 * k.Length;
                    engine.Key     <- k;

                    begin
                        match m with
                        | ECB ->
                            engine.Mode <- CipherMode.ECB

                        | CBC iv ->
                            engine.Mode <- CipherMode.CBC;
                            engine.IV   <- iv
                    end;

                    new CSPBlockCipher (name, d, engine) :> BlockCipher
            in
                match m with
                | None               -> Some (of_csp_mode ECB)
                | Some (mode.CBC iv) -> Some (of_csp_mode (CBC iv))
                | Some (mode.GCM _ ) -> None

        member self.StreamCipher (d : direction) (c : scipher) (k : key) =
            None

        member self.HMac (name : string) (k : key) =
            None
