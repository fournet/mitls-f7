#light "off"

module Application

open Attack_Alert
open Handshake_full_RSA
open Handshake_full_DHE


[<EntryPoint>]
let main argv = 
    
    (* Alert attack *)
    //Attack_Alert.run "www.google.com";
    
    (* Standard RSA full handshake as Client*)
    Handshake_full_RSA.client("www.inria.fr");
    printf "RSA client finished\n";

    (* Standard RSA full handshake with client authentication as Client *)
    //Handshake_full_RSA.client_with_auth("127.0.0.1","rsa.cert-01.mitls.org",4433);
    //printf "RSA client finished\n";
    
    (* Standard RSA full handshake as Server *)
    //printf "Running RSA server. Please connect to port 4433\n";
    //Handshake_full_RSA.server("0.0.0.0","rsa.cert-01.mitls.org",4433);
    //printf "RSA server finished\n";

    (* Standard DHE full handshake as Client *)
    Handshake_full_DHE.client("www.inria.fr");
    printf "DHE client finished\n";

    (* Standard DHE full handshake as Server *)
    //Handshake_full_DHE.server("127.0.0.1","rsa.cert-01.mitls.org",4433);
    //printf "DHE server finished\n";

    ignore (System.Console.ReadLine());
    0
