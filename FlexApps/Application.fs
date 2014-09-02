#light "off"

module Application

[<EntryPoint>]
let main argv = 
    //AlertAttack.alertAttack "www.google.com";
    
    //RSA_KEX.RSA_KEX.client("www.inria.fr");
    //printf "RSA client finished\n";
    
    printf "Running RSA server. Please connect to port 4433\n";
    RSA_KEX.RSA_KEX.server("0.0.0.0","rsa.cert-01.mitls.org",4433);
    printf "RSA server finished\n";
    ignore (System.Console.ReadLine());
    0