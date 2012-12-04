module Ranges

open System

let FS = 16384
let PS = 255
let BS = 16
let t  = 20

let rangeSplit (l:int) (h:int) =
    if l >= FS then
        (FS,FS),(l-FS,h-FS)
    else
        let z0 = PS - ((PS + t + 1) % BS) in
        let zl = PS - ((l + PS + t + 1) % BS) in
        if l = 0 then
            let p = h-l in
            let fh = min p z0 in
            (0,fh),(0,h-fh)
        else
            let p = (h-l) % z0 in
            if (p <= zl) && (l+p <= FS) then
                (l,l+p),(0,h-(l+p))
            else
                (l,l),(0,h-l) 
        
let fragment (len:int) (l,h) =
    let ((fl,fh),(l',h')) = rangeSplit l h in
    printf "(%3d,%3d)" fl fh
    let f = min len fh in
    (f,fh-f),(len-f,(l',h'))

let rec loop l h len =
    if h > 0 then
        let ((flen,fpad),(len',(l',h'))) = fragment len (l,h) in
        printf " [%3d,%3d] (%3d,%3d)\n" flen fpad l' h'
        loop l' h' len'

let rec main () =
    printf "Give Range\n"
    let l = Int32.Parse(Console.ReadLine())
    let h = Int32.Parse(Console.ReadLine())
    printf "Give Length\n"
    let len = Int32.Parse(Console.ReadLine())
    loop l h len
    main ()

let _ = main ()
