require import Option.
require import Int. 
require import Real. 
require import Distr. 
require import List. 
require import FSet. 

(*** Some type definitions *) 
(** Our PRG uses a type for internal keys 
    and a type for its output. *) 

type parameter.
type key. 
op dkey: key distr. 

axiom dkeyL: mu dkey True = 1%r. 
axiom dkeyU: isuniform dkey. 
axiom dkeyF (x:key): in_supp x dkey. 

(* op pr_dkey = mu_x dkey witness. *)

type input.
type output. 

op dout: output distr. 
axiom doutL: mu dout True = 1%r. 
 
(** We use an agile PRF that, on input an agility parameter and a key, 
    produces an output... *) 
module type AgilePRF = { 
  proc * init() : unit 
  proc f(p:parameter,k:key,x:input): output 
}. 

theory UCR.
  
    const P : parameter set.
   
    const pp : parameter. 
     
    op key : key distr.
     
    module type Oracle = {
      proc f(p:parameter, x:input) : output option
    }.
   
    module type Adversary(O:Oracle) = {
      proc find() : key * input * parameter * key * input
    }.

    module Wrap(P:AgilePRF) : Oracle = { 
      var k: key
      proc f(p:parameter, x:input) : output option = {
        var oo:output option;
        var o:output;
        oo = None;
        if (mem p P) { 
          
          o = P.f(p, k, x);
          oo = Some o; 
        }
        return oo;
      }
    }.
    
    module UCR(P:AgilePRF, A:Adversary) = {
      module O = Wrap(P)
      module A = A(O)
     
      proc main() : bool = {
        return false;
      }
    }.
  

type label.
type record.
type key_output.
op dkey_output: key_output distr.
type purpose = [Client_Finished | Server_Finished].
type text.
type tag_output.
op dtag_output: tag_output distr.


module type AgileKDF_MAC = {
  proc * init() : unit
  proc kdf(p:parameter,k:key,l:label,r:record): key_output
  proc mac(p:parameter,k:key,t:purpose,v:text): tag_output
}.

op truncate_tag: parameter -> output -> tag_output.
op truncate_record: record -> output -> key_output.

op kdf_encode: label -> input.
op mac_encode: purpose -> text -> input.

module AgileKDF_MAC(P:AgilePRF): AgileKDF_MAC = {
  proc init() : unit = {
  }
  proc kdf(p:parameter,k:key,l:label,r:record): key_output= {
    var o:output;
    o = P.f(p,k,kdf_encode l);
    return truncate_record r o;
  }

  proc mac(p:parameter,k:key,t:purpose,v:text): tag_output= {
    var o:output;
    o = P.f(p,k,mac_encode t v);
    return truncate_tag p o;
  }
 
}.