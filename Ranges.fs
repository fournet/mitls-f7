open System

let FS = 10000
let PS = 200

let rec ranges a b =
    let minpack = (b-a) / PS
    let minfrag = (b-1) / FS
    let savebytes = Math.Max(minpack,minfrag)
    //printf "minpack = %d\n" minpack
    let smalla = Math.Max (Math.Min (a-savebytes,FS), 0)
    let smallb = Math.Min (Math.Min (PS+smalla, FS), b)
    printf "(%d,%d); " smalla smallb
    let a = a-smalla
    let b = b-smallb
    if b > 0 then
        ranges a b

let rec main () =
    printf "Give Range\n"
    let a = Int32.Parse(Console.ReadLine())
    let b = Int32.Parse(Console.ReadLine())
    //printf "a = %d; b = %d\n" a b
    ranges a b
    printf "\n"
    main ()

let _ = main ()