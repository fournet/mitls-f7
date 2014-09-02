#light "off"

module Attacks

[<EntryPoint>]
let main argv = 
    AlertAttack.alertAttack "www.google.com";
    0