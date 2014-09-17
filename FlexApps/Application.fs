#light "off"

module Application

open FlexTypes
open Attack_Alert
open Attack_FragmentClientHello
open Attack_EarlyCCS
open Handshake_full_RSA
open Handshake_full_DHE
open Handshake_resumption


[<EntryPoint>]
let main argv = 
    
    (* Alert attack *)
    //Attack_Alert.run "www.google.com";
    
    (* Protocol downgrade attack (Fragmented ClientHello) *)
    //Attack_FragmentClientHello.run("www.inria.fr",fp=All(5));
    //printf "Protocol version downgrade attack finished\n";

    (* Early CCS attack *)
    //Attack_EarlyCCS.run("128.93.189.207",4433);
    //printf "Early CCS attack finished\n";

    (* Standard RSA full handshake as Client *)
    let st = Handshake_full_RSA.client("www.inria.fr") in
    printf "RSA client finished\n";

    (* Standard RSA full handshake with client authentication as Client *)
    //let st = Handshake_full_RSA.client_with_auth("127.0.0.1","rsa.cert-01.mitls.org",44101) in
    //printf "RSA client_auth finished\n";
    
    (* Standard DHE full handshake as Client *)
    //let st = Handshake_full_DHE.client("www.inria.fr") in
    //printf "DHE client finished\n";

    (* Standard DHE full handshake with client authentication as Client *)
    //let st = Handshake_full_DHE.client_with_auth("127.0.0.1","rsa.cert-01.mitls.org",44102) in
    //printf "DHE client_auth finished\n";

    (* Standard RSA full handshake as Server *)
    //printf "Running RSA server. Please connect to port 44201\n";
    //let st = Handshake_full_RSA.server("0.0.0.0","rsa.cert-01.mitls.org",44201) in
    //printf "RSA server finished\n";

    (* Standard RSA full handshake with client authentication as Server *)
    //printf "Running RSA server. Please connect to port 44202\n";
    //let st = Handshake_full_RSA.server_with_client_auth("0.0.0.0","rsa.cert-01.mitls.org",44202) in
    //printf "RSA server_with_client_auth finished\n";

    (* Standard DHE full handshake as Server *)
    //printf "Running RSA server. Please connect to port 44203\n";
    //let st = Handshake_full_DHE.server("127.0.0.1","rsa.cert-01.mitls.org",44203) in
    //printf "DHE server finished\n";

    (* Standard DHE full handshake with client authentication as Server *)
    //printf "Running RSA server. Please connect to port 44204\n";
    //let st = Handshake_full_DHE.server_with_client_auth("127.0.0.1","rsa.cert-01.mitls.org",44204) in
    //printf "DHE server_with_client_auth finished\n";

    (* Standard RSA full handshake then resume both as Client *)
    let st = Handshake_full_RSA.client("www.inria.fr") in
    // TODO: Close current connection
    let st = Handshake_resumption.client(st,"www.inria.fr") in
    printf "RSA client resumption finished\n"; 

    ignore (System.Console.ReadLine());
    0
