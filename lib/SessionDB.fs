module SessionDB

open Error_handling

type store<'k,'v when 'k:comparison> = Map<'k,'v>

let create () = Map.empty

let select map key = Map.tryFind key map

let insert map key value = Map.add key value map

let remove map key = Map.remove key map