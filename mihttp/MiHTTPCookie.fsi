﻿module MiHTTPCookie

open Bytes

type cookie = {
  name   : string;
  value  : string;
  domain : string;
  path   : string;
  maxage : int;
  secure : bool;
}

type ckenv = {
    path   : string;
    domain : string;
}

val parse : ckenv -> bytes -> cookie list