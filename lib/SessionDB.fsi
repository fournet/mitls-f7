module SessionDB

open Error_handling

type store<'k,'v when 'k:comparison> = Map<'k,'v>

val create: unit -> store<'k,'v>
val select: store<'k,'v> -> 'k -> 'v Option
val insert: store<'k,'v> -> 'k -> 'v -> store<'k,'v>
val remove: store<'k,'v> -> 'k -> store<'k,'v>