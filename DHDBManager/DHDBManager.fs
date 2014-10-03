module DHDBManager

open Bytes
open System
open System.IO

open Microsoft.FSharp.Text
open Org.BouncyCastle.Math
open Org.BouncyCastle.Utilities.IO.Pem
open Org.BouncyCastle.Asn1


type dh_params =
 | DH  of bytes * bytes
 | DHX of bytes * bytes * bytes

type command = 
  | Check
  | Dump
  | Insert
  | Import  

type options = {
    command: command;
    dbfile:  string;  
    dbfile2: string;
    pemfile: string;
    dumpdir: string;
    minplen: int;
    minqlen: int;
    confidence: int;
    force: bool;
}

exception ArgError of string
exception InvalidPEMFile of string


(* ------------------------------------------------------------------------ *)
let PEM_DH_PARAMETERS_HEADER  = "DH PARAMETERS"       (* p, g, [len] *)
let PEM_DHX_PARAMETERS_HEADER = "X9.42 DH PARAMETERS" (* p, q, g, [j, validation] *)

(* ------------------------------------------------------------------------ *)
let load_params (stream : Stream) : dh_params =
    let reader = new PemReader(new StreamReader(stream))
    let obj    = reader.ReadPemObject() in

    if obj.Type = PEM_DH_PARAMETERS_HEADER then
        let obj = DerSequence.GetInstance(Asn1Object.FromByteArray(obj.Content)) in
        if obj.Count < 2 then
            raise (InvalidPEMFile(sprintf "Expecting at least 2 parameters, got %d" obj.Count))
        else
             DH (abytes (DerInteger.GetInstance(obj.Item(0)).PositiveValue.ToByteArrayUnsigned()),
                 abytes (DerInteger.GetInstance(obj.Item(1)).PositiveValue.ToByteArrayUnsigned()))
        
    else if obj.Type = PEM_DHX_PARAMETERS_HEADER then
        let obj = DerSequence.GetInstance(Asn1Object.FromByteArray(obj.Content)) in
        if obj.Count < 3 then
            raise (InvalidPEMFile(sprintf "Expecting at least 3 parameters, got %d" obj.Count))
        else
            DHX (abytes (DerInteger.GetInstance(obj.Item(0)).PositiveValue.ToByteArrayUnsigned()),
                 abytes (DerInteger.GetInstance(obj.Item(1)).PositiveValue.ToByteArrayUnsigned()),
                 abytes (DerInteger.GetInstance(obj.Item(1)).PositiveValue.ToByteArrayUnsigned()))
    
    else
        raise (InvalidPEMFile(sprintf "Unrecognized PEM header: %s" obj.Type))

(* ------------------------------------------------------------------------ *)
let load_params_from_file (file : string) : dh_params =
    let filestream = new FileStream(file, FileMode.Open, FileAccess.Read) in
    try
        load_params filestream
    finally
        filestream.Close()

(* ------------------------------------------------------------------------ *)
let save_params (stream:Stream) (dhp:dh_params) =
    let writer    = new PemWriter(new StreamWriter(stream)) in
    match dhp with
    | DH(p,g) ->
        let derparams = 
            new DerSequence([| new DerInteger(new BigInteger(1, cbytes p)) :> Asn1Encodable;
                               new DerInteger(new BigInteger(1, cbytes g)) :> Asn1Encodable |])
            :> Asn1Encodable
        in
            writer.WriteObject(new PemObject(PEM_DH_PARAMETERS_HEADER, derparams.GetDerEncoded()))
    | DHX(p,q,g) ->
        let derparams = 
            new DerSequence([| new DerInteger(new BigInteger(1, cbytes p)) :> Asn1Encodable;
                               new DerInteger(new BigInteger(1, cbytes q)) :> Asn1Encodable;
                               new DerInteger(new BigInteger(1, cbytes g)) :> Asn1Encodable |])
            :> Asn1Encodable
        in
            writer.WriteObject(new PemObject(PEM_DHX_PARAMETERS_HEADER, derparams.GetDerEncoded()))
    writer.Writer.Flush()

(* ------------------------------------------------------------------------ *)
let save_params_to_file (file:string) (dhp:dh_params) =
    let filestream = new FileStream(file, FileMode.Create, FileAccess.Write) in
    try
        try
            save_params filestream dhp
        finally
            filestream.Close()
    with _ ->
        failwith "unexpected"

(* ------------------------------------------------------------------------ *)
let check_unknown_q conf minPl minQl pbytes gbytes : bool =
    let p = new BigInteger(1, cbytes pbytes)
    let g = new BigInteger(1, cbytes gbytes)
    let pm1 = p.Subtract(BigInteger.One)
    let q = pm1.Divide(BigInteger.Two) in
        (g.CompareTo BigInteger.One) > 0 && (g.CompareTo pm1) < 0 &&
        minPl <= p.BitLength && minQl <= q.BitLength &&
        p.IsProbablePrime(conf) && q.IsProbablePrime(conf)

(* ------------------------------------------------------------------------ *)
let check_known_q conf minPl minQl pbytes gbytes qbytes : bool =
    let p = new BigInteger(1, cbytes pbytes) 
    let g = new BigInteger(1, cbytes gbytes) 
    let q = new BigInteger(1, cbytes qbytes) 
    let pm1 = p.Subtract(BigInteger.One) in 
    if (g.CompareTo BigInteger.One) > 0 && (g.CompareTo pm1) < 0 &&
       minPl <= p.BitLength && minQl <= q.BitLength &&
       p.IsProbablePrime(conf) && q.IsProbablePrime(conf) then
        let r = g.ModPow(q, p)
        // For OpenSSL-generated parameters order(g) = 2q, so e^q mod p = p-1
        r.Equals(BigInteger.One) || r.Equals(pm1)
    else
        false

(* ------------------------------------------------------------------------ *)
let insert_safe_prime dhdb pbytes gbytes : DHDB.dhdb =
    let p   = new BigInteger(1, cbytes pbytes)
    let pm1 = p.Subtract(BigInteger.One)        
    let q   = pm1.Divide(BigInteger.Two)
    let qbytes = abytes (q.ToByteArrayUnsigned()) in                 
        DHDB.insert dhdb (pbytes, gbytes) (qbytes, true)

(* ------------------------------------------------------------------------ *)
let insert_known_q dhdb pbytes gbytes qbytes db : DHDB.dhdb =
    let p   = new BigInteger(1, cbytes pbytes)
    let q   = new BigInteger(1, cbytes qbytes)    
    let pm1 = p.Subtract(BigInteger.One)        
    let q'  = pm1.Divide(BigInteger.Two) in
        DHDB.insert dhdb (pbytes, gbytes) (qbytes, q.Equals(q'))

(* ------------------------------------------------------------------------------- *)
let dump db dir =
    let keys = DHDB.keys db in
    let n = ref 1u in
        for (p,g) in keys do
            match DHDB.select db (p,g) with
            | None -> failwith "unexpected"
            | Some(q,b) ->
                save_params_to_file (sprintf "%s/dhparams_%u.pem" dir !n) (DHX(p,q,g));
                n := !n + 1u

(* ------------------------------------------------------------------------------- *)
let check conf minPl minQl db =
    let keys = DHDB.keys db in
        for (pbytes,gbytes) in keys do
            match DHDB.select db (pbytes,gbytes) with
            | None -> failwith "unexpected"
            | Some(qbytes,true) ->
                let p   = new BigInteger(1, cbytes pbytes)
                let q   = new BigInteger(1, cbytes qbytes)    
                let pm1 =  p.Subtract(BigInteger.One)        
                let q'  = pm1.Divide(BigInteger.Two) in
                    if not(q.Equals(q')) || not(check_unknown_q conf minPl minQl pbytes gbytes) then 
                        eprintfn "Found an invalid parameter";
                        exit 1
            | Some(qbytes,false) ->
                let p   = new BigInteger(1, cbytes pbytes)
                let q   = new BigInteger(1, cbytes qbytes)    
                let pm1 = p.Subtract(BigInteger.One)        
                let q'  = pm1.Divide(BigInteger.Two) in
                    if q.Equals(q') then
                        eprintfn "Found parameter with a safe prime modulus but an unset safe prime flag";
                        exit 1
                    else
                        if not(check_known_q conf minPl minQl pbytes gbytes qbytes) then
                            eprintfn "Found an invalid parameter";
                            exit 1                    

(* ------------------------------------------------------------------------ *)
let cmdParse () = 
    let assembly = System.Reflection.Assembly.GetExecutingAssembly()
    let mypath   = Path.GetDirectoryName(assembly.Location)
    let myname   = Path.GetFileNameWithoutExtension(assembly.Location)

    let defaultDBFile  = TLSInfo.defaultConfig.dhDBFileName
    let defaultMinPlen = fst TLSInfo.defaultConfig.dhPQMinLength
    let defaultMinQlen = snd TLSInfo.defaultConfig.dhPQMinLength
    let defaultDumpDir = "dhdb_dump"
  
    let options = ref {
        command = Dump;
        dbfile  = Path.Combine(mypath, defaultDBFile); 
        dbfile2 = "";
        pemfile = "";
        dumpdir = Path.Combine(mypath, defaultDumpDir);
        minplen = defaultMinPlen;
        minqlen = defaultMinQlen; 
        force   = false; 
        confidence = 80; }

    let o_dbfile = fun s ->
        options := { !options with dbfile = s }

    let o_pemfile = fun s ->
        if not (File.Exists s) then
            let msg = sprintf "File not found: %s" s in
                raise (ArgError msg);
        options := { !options with command = Insert; pemfile = s }

    let o_dumpdir = fun s ->
        options := { !options with command = Dump; dumpdir = s }
        
    let o_dbfile2 = fun s ->
        if not (File.Exists s) then
            let msg = sprintf "File not found: %s" s in
                raise (ArgError msg);
        options := { !options with command = Import; dbfile2 = s }

    let o_check = fun () ->
        options := { !options with command = Check }
    
    let o_force = fun () ->
        options := { !options with force = true }
    
    let o_minplen = fun n ->
        if n < 0 then
            let msg = sprintf "Length must be non-negative, given %d" n in
                raise (ArgError msg);
        options := { !options with minplen = n }

    let o_minqlen = fun n ->
        if n < 0 then
            let msg = sprintf "Length must be non-negative, given %d" n in
                raise (ArgError msg);
        options := { !options with minqlen = n }

    let o_confidence = fun n ->
        if n <= 0 then
            let msg = sprintf "Confidence level must be positive, given %d" n in
                raise (ArgError msg);
        options := { !options with confidence = n }

    let specs = [
        "-db",        ArgType.String o_dbfile  , "Database file (creates an empty one if it does not exist)"
        "-insert",    ArgType.String o_pemfile , "Insert parameters stored in a PEM file"
        "-dump",      ArgType.String o_dumpdir , "Dump entries in the database as PEM files in the directory specified"
        "-check",     ArgType.Unit o_check     , "Check the validity of parameters in the database"
        "-import",    ArgType.String o_dbfile2 , "Import all parameters from given database"
        "-minPlen",   ArgType.Int o_minplen    , "Minimum modulus length in bits (used for validation)"
        "-minQlen",   ArgType.Int o_minqlen    , "Minimum subgroup size in bits (used for validation)"
        "-confidence",ArgType.Int o_confidence , "Confidence level for primality checks"
        "-force",     ArgType.Unit o_force     , "Do not validate parameters before inserting or importing them"   
    ]

    let specs = specs |> List.map (fun (sh, ty, desc) -> ArgInfo(sh, ty, desc))

    let args = System.Environment.GetCommandLineArgs()

    let usage = sprintf "Usage: %s options" myname

    try
      ArgParser.Parse (specs, usageText = usage);
      !options

    with ArgError msg ->
        ArgParser.Usage(specs, sprintf "Error: %s\n\n%s" msg usage);
        exit 1
            
(* ------------------------------------------------------------------------------- *)
[<EntryPoint>]
let _ =
    let options = cmdParse ()

    let db = 
        try 
            DHDB.create options.dbfile
        with _ ->
            eprintf "Could not open or create database: %s" options.dbfile;
            exit 1
 
    match options.command with    
    | Insert ->
        let dhp =
            try load_params_from_file options.pemfile
            with InvalidPEMFile s -> 
                eprintfn "Invalid PEM file. %s" s;
                exit 1
        in
            match dhp with
            | DH(p,g) -> 
                match DHDB.select db (p,g) with
                | Some _ -> 
                    eprintfn "Found parameters in the database with same modulus and generator";
                    exit 1
                | _ ->            
                    if options.force || check_unknown_q options.confidence options.minplen options.minqlen p g then
                        ignore(insert_safe_prime db p g);
                        exit 0
                    else
                        eprintfn "Could not validate the parameters";
                        exit 1
            | DHX(p,q,g) ->
                match DHDB.select db (p,g) with
                | Some _ -> 
                    eprintfn "Found parameters in the database with same modulus and generator";
                    exit 1
                | _ ->            
                    if options.force || check_known_q options.confidence options.minplen options.minqlen p g q then
                        ignore(insert_known_q db p g q);
                        exit 0
                    else
                        eprintfn "Could not validate the parameters";
                        exit 1       

    | Dump -> 
        try 
            let di = Directory.CreateDirectory options.dumpdir in
            dump db options.dumpdir;
            exit 0
        with _ ->
            eprintf "Could not open or create directory: %s" options.dumpdir;
            exit 1

    | Check ->
        check options.confidence options.minplen options.minqlen db;
        exit 0

    | Import ->
        try 
            ignore (DHDB.merge db options.dbfile2);
            exit 0
        with _ ->
            eprintfn "Some error";
            exit 1
