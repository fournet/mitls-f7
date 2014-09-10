#light "off"

module Application




[<EntryPoint>]
let main argv = 
    
    (* Alert attack *)
    //AlertAttack.alertAttack "www.google.com";
    
    (* Standard RSA full handshake as Client*)
    //RSA_KEX.RSA_KEX.client("www.inria.fr");
    //printf "RSA client finished\n";

    (* Standard RSA full handshake with client authentication as Client *)
    RSA_KEX.RSA_KEX.client_with_auth("127.0.0.1","rsa.cert-01.mitls.org",4433);
    printf "RSA client finished\n";
    
    (* Standard RSA full handshake as Server *)
    //printf "Running RSA server. Please connect to port 4433\n";
    //RSA_KEX.RSA_KEX.server("0.0.0.0","rsa.cert-01.mitls.org",4433);
    //printf "RSA server finished\n";

    ignore (System.Console.ReadLine());
    0
