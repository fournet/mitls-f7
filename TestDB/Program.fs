open DHDB
open Serialization
open Bytes
open CoreRandom
open TLSInfo
open TLSConstants

open System.IO

open Org.BouncyCastle.Math
open Org.BouncyCastle.Security


let n = 3

(* ------------------------------------------------------------------------------- *)
let insert_dh () =
    let dhdb = DHDB.create "dh.db" in
    let gen = new SecureRandom() in
    let all = 
     [for i in 1 .. n do
        let p = new BigInteger(1024, gen) in
        let q = new BigInteger(1024, gen) in
        let g = new BigInteger(1024, gen) in
        let b = (i%2).Equals(0) in
        yield (p,g,q,b) ]
    in
    let all = List.sortBy (function (p,g,q,b) -> p.ToString()) all in
    for p,g,q,b in all do 
        let pbytes = abytes (p.ToByteArrayUnsigned()) in
        let qbytes = abytes (q.ToByteArrayUnsigned()) in
        let gbytes = abytes (g.ToByteArrayUnsigned()) in
            printfn "p=%O\ng=%O\nq=%O\nb=%b" p g q b;
            ignore(DHDB.insert dhdb (pbytes, gbytes) (qbytes, b))
    done
    ()

(* ------------------------------------------------------------------------------- *)
let dump_dh () =
    let dhdb = DHDB.create "dh.db" in
    let keys = DHDB.keys dhdb in
    let keys = List.sortBy (function (p,g) -> let p = new BigInteger(1, cbytes p) in p.ToString()) keys in
    for (p,g) in keys do
        match DHDB.select dhdb (p,g) with
        | None -> failwith "unexpected"
        | Some(q,b) ->
          let p = new BigInteger(1, cbytes p) in
          let g = new BigInteger(1, cbytes g) in
          let q = new BigInteger(1, cbytes q) in
            printfn "p=%O\ng=%O\nq=%O\nb=%b" p g q b;
    done
    ()

(* ------------------------------------------------------------------------------- *)
let insert_session () =
    let db = SessionDB.create {TLSInfo.defaultConfig with sessionDBFileName="session.db"} in    
    let all = 
      [for i in 1 .. n do
        let id = CoreRandom.random(32) in
        let role = if (i%2).Equals(0) then TLSInfo.Client else TLSInfo.Server in
        let hint = sprintf "This is a hint %d" i in
        let si = {
            init_crand = CoreRandom.random(6);
            init_srand = CoreRandom.random(7);
            protocol_version = TLS_1p1;
            cipher_suite = cipherSuite_of_name TLS_DH_anon_WITH_AES_256_GCM_SHA384;
            compression = NullCompression;
            extensions = {ne_extended_ms = (i%2).Equals(0); ne_extended_padding=(i%2).Equals(1); ne_renegotiation_info = Some (random(4), random(4))};
            pmsId = noPmsId;
            session_hash = CoreRandom.random(5);
            client_auth = true;
            clientID = [CoreRandom.random(10)];
            clientSigAlg = SA_DSA, NULL;
            serverID = [CoreRandom.random(4)];
            serverSigAlg = SA_ECDSA, SHA384;
            sessionID = CoreRandom.random(12);
            } in
        let ms = PRF.coerce (StandardMS (noPmsId, Nonce.random 2, PRF_SSL3_nested)) 
                        (CoreRandom.random(16)) in
        let epoch = TLSInfo.unAuthIdInv ({ 
                                            msId = StandardMS (noPmsId, Nonce.random 64, PRF_SSL3_nested); 
                                            kdfAlg=PRF_SSL3_nested; 
                                            pv=SSL_3p0; 
                                            aeAlg= MACOnly(MA_SSLKHASH(NULL)); 
                                            csrConn = Nonce.random 4;
                                            ext = {ne_extended_padding = false; ne_extended_ms = false; ne_renegotiation_info = None};
                                            writer=Client
            }) 
        in yield (id,role,hint,si,ms,epoch) ] in    
    let all = List.sortBy (function (id:bytes,role,hint,si,ms,epoch) -> hint) all in
    for id,role,hint,si,ms,epoch in all do
        let dummy = StandardMS (noPmsId, empty_bytes, TLSConstants.PRF_SSL3_nested) in
        printfn "%s\n%s\n%s\n%s\n%A" 
                    (hexString id) hint (sinfo_to_string si) (hexString (PRF.leak dummy ms)) epoch
        ignore(SessionDB.insert db id role hint (si, ms, epoch))
    done
    ()

(* ------------------------------------------------------------------------------- *)
let dump_session () =
    let db = SessionDB.create {TLSInfo.defaultConfig with sessionDBFileName="session.db"} in
    let keys = SessionDB.getAllStoredIDs db in
    let keys = List.sortBy (function (_,_,hint) -> hint) keys in
    for (id,role,hint) in keys do
        match SessionDB.select db id role hint with
        | None -> failwith "unexpected"
        | Some(si,ms,epoch) -> 
            let dummy = StandardMS (noPmsId, empty_bytes, TLSConstants.PRF_SSL3_nested) in
            printfn "%s\n%s\n%s\n%s\n%A" 
                    (hexString id) hint (sinfo_to_string si) (hexString (PRF.leak dummy ms)) epoch
    done
    ()

[<EntryPoint>]
let main argv = 
//    if File.Exists "dh.db" then    
//        dump_dh ();
//    else
//        insert_dh ();

    if File.Exists "session.db" then    
        dump_session ();
    else
        insert_session (); 

    0
