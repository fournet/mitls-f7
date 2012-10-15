module EchoTest

open System
open System.IO
open System.Text

open Microsoft.FSharp.Text
open Microsoft.FSharp.Reflection

(* ------------------------------------------------------------------------ *)
exception NotAValidEnumeration

let enumeration<'T> () =
    let t = typeof<'T>

    if not (FSharpType.IsUnion(t)) then
        raise NotAValidEnumeration;

    let cases = FSharpType.GetUnionCases(t)

    if not (Array.forall
                (fun (c : UnionCaseInfo) -> c.GetFields().Length = 0)
                (FSharpType.GetUnionCases(t))) then
        raise NotAValidEnumeration;

    let cases =
        Array.map
            (fun (c : UnionCaseInfo) ->
                (c.Name, FSharpValue.MakeUnion(c, [||]) :?> 'T))
            cases
    in
        cases

(* ------------------------------------------------------------------------ *)
let cs_map = enumeration<CipherSuites.cipherSuiteName> ()
let vr_map = [| ("ssl3"  , CipherSuites.SSL_3p0) ;
                ("tls1.0", CipherSuites.TLS_1p0) ;
                ("tls1.1", CipherSuites.TLS_1p1) ;
                ("tls1.2", CipherSuites.TLS_1p2) ; |]

(* ------------------------------------------------------------------------ *)
let parse_cipher  = let map = Map.ofArray cs_map in fun x -> map.TryFind x
let parse_version = let map = Map.ofArray vr_map in fun x -> map.TryFind x

(* ------------------------------------------------------------------------ *)
exception ArgError of string

let parse_cmd () =
    let assembly = System.Reflection.Assembly.GetExecutingAssembly()
    let mypath   = Path.GetFileName(assembly.Location)

    let options : EchoServer.options ref = ref {
        ciphersuite = [ CipherSuites.TLS_RSA_WITH_RC4_128_SHA ];
        tlsversion  = CipherSuites.TLS_1p0;
        servername  = "needham.inria.fr";
        clientname  = None; }
    in

    let o_ciphers (ciphers : string) =
        let ciphers =
            let parse cipher =
                match parse_cipher cipher with
                | None        -> raise (ArgError (sprintf "invalid cipher-suite: `%s'" cipher))
                | Some cipher -> cipher
            in
                match ciphers.Split(':') with
                | a when a.Length = 0 -> raise (ArgError "empty ciphers list")
                | a -> Array.toList (Array.map parse (ciphers.Split(':')))
        in
            options := { !options with ciphersuite = ciphers }
    
    let o_version (version : string) =
        match parse_version version with
        | None -> raise (ArgError (sprintf "invalid TLS version: `%s'" version))
        | Some version -> options := { !options with tlsversion = version }

    let o_client_name (name : string) =
        options := { !options with clientname = Some name }

    let o_server_name (name : string) =
        options := { !options with servername = name }

    let o_list () =
        let all = [ ("ciphers"     , Array.toList (Array.map (fun (k, _) -> k) cs_map));
                    ("TLS versions", Array.toList (Array.map (fun (k, _) -> k) vr_map)); ]
        in
            List.iter
                (fun (head, values) ->
                    printfn "Supported %s:" head
                    List.iter (fun x -> printfn "  %s" x) values
                    printfn "")
                all;
            exit 2

    let specs =
        let specs = [
            "--ciphers"    , ArgType.String o_ciphers    , ":-separated ciphers list"
            "--tlsversion" , ArgType.String o_version    , "TLS version to accept / propose"
            "--client-name", ArgType.String o_client_name, "TLS client name"
            "--server-name", ArgType.String o_server_name, (sprintf "TLS server name (default: %s)" (!options).servername)
            "--list"       , ArgType.Unit   o_list       , "Print supported version/ciphers and exit" ]
        in
            specs |> List.map (fun (sh, ty, desc) -> ArgInfo(sh, ty, desc))

    in
        try
            ArgParser.Parse(specs, usageText = sprintf "Usage: %s <options>" mypath); !options

        with ArgError msg ->
            ArgParser.Usage(specs, sprintf "Error: %s\n" msg);
            exit 1

(* ------------------------------------------------------------------------ *)
let _ = EchoServer.entry (parse_cmd ())
