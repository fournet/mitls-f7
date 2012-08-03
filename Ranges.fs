module Ranges

open System

let FS = 16384
let PS = 255 - 16

let ranges a b =
    let minpack = (b-a) / PS
    let minfrag = (b-1) / FS
    let savebytes = Math.Max(minpack,minfrag)
    let smalla = Math.Max (Math.Min (a-savebytes,FS), 0)
    let smallb = Math.Min (Math.Min (PS+smalla, FS), b)
    ((smalla,smallb),(a-smalla,b-smallb))

let content (sa,sb) (a,b) l =
    if l > b then
        let sl = Math.Min(l-a,FS)
        (sl,l-sl)
    else
        (0,l)

let rec loop sa sb a b l =
    if b > 0 then
        printf " [%d,%d]" a b
        let (sl,l) = content (sa,sb) (a,b) l
        printf " %d\n" sl
        let ((sa,sb),(a,b)) = ranges a b
        printf "(%d,%d)" sa sb
        loop sa sb a b l

let rec main () =
    printf "Give Range\n"
    let mutable a = Int32.Parse(Console.ReadLine())
    let mutable b = Int32.Parse(Console.ReadLine())
    printf "Give Length\n"
    let mutable l = Int32.Parse(Console.ReadLine())
    let ((sa,sb),(a,b)) = ranges a b
    printf "(%d,%d)" sa sb
    loop sa sb a b l
    printf " %d\n" l
    main ()

let _ = main ()
