module Ranges

open System

let FS = 16384
let PS = 255
let BS = 16
let t  = 20

let rangeSplit (l:int) (h:int) =
    let z = PS - ((PS + t + 1) % BS) in
    let p = h - l in
    if p > 0 then
        if p >= z then
            ((0,z),(l,h-z))
        else
            let fl = l % FS in
            let o = (fl + PS + t + 1) % BS in
            let fh = min (min (fl+PS-o) (fl+p)) FS in
            let pnext = (h-fh)-(l-fl) in
            if pnext = 0 then
                ((fl,fh),(l-fl,h-fh))
            else
                ((0,pnext),(l,h-pnext))
    else
        let f = min l FS in
        ((f,f),(l-f,h-f))

let fragment (len:int) (l,h) =
    let ((fl,fh),(l',h')) = rangeSplit l h in
    printf "(%3d,%3d)" fl fh
    let f = max (len-h') fl in
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
