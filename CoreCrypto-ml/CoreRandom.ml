let rng = Random.self_init()
let random (i : int) =
    if i < 0 then
        failwith "length must be non-negative";
    
    let bytes = String.make i (char_of_int 0) in
    for x = 0 to i-1 do 
        let c = char_of_int (Random.int 256) in
        String.set bytes x c
    done;
    Bytes.abytes bytes
