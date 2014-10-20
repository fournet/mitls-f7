module CoreECDH

open Org.BouncyCastle.Math
open Org.BouncyCastle.Crypto
open Org.BouncyCastle.Crypto.Digests
open Org.BouncyCastle.Crypto.Generators
open Org.BouncyCastle.Crypto.Signers
open Org.BouncyCastle.Crypto.Parameters
open Org.BouncyCastle.Math.EC
open Org.BouncyCastle.Security

val getcurve : string -> FpCurve * ECDomainParameters * FpPoint