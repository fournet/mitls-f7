module RSA

// CF The check_client_... flag is included in the CRE-RSA assumption, 
// CF which seens even stronger if the adversary can choose the flag value.
(* MK 

   See http://tools.ietf.org/html/rfc5246#section-7.4.7.1
   
   The version number in the PreMasterSecret is the version
   offered by the client in the ClientHello.client_version, not the
   version negotiated for the connection.  This feature is designed to
   prevent rollback attacks.  

   Client implementations MUST always send the correct version number in
   PreMasterSecret.  If ClientHello.client_version is TLS 1.1 or higher,
   server implementations MUST check the version number as described in
   the note below.  If the version number is TLS 1.0 or earlier, server
   implementations SHOULD check the version number, but MAY have a
   configuration option to disable the check.  

*)

open Bytes
open Error
open TLSConstants
open TLSInfo
open RSAKey

#if ideal
// We maintain a log to look up ideal_pms values using dummy_pms values.
type entry = (pk * ProtocolVersion * bytes) *  CRE.rsapms
let log = ref []
#endif

let encrypt pk pv pms =
    //#begin-ideal1
    let plaintext = 
    #if ideal
    //MK Here we rely on every pms being encrypted only once. 
    //MK Otherwise we would have to story dummy_pms values to maintain consistency.
      if (* MK redundant RSAKey.honest pk  && *) CRE.honestRSAPMS pk pv pms then
        let dummy_pms = versionBytes pv @| random 46
        log := ((pk,pv,dummy_pms),pms)::!log
        dummy_pms
      else
    #endif
        CRE.leakRSA pk pv pms       
    //#end-ideal1
    let epms = CoreACiphers.encrypt_pkcs1 (RSAKey.repr_of_rsapkey pk) plaintext
    #if ideal
    Pi.assume(CRE.EncryptedRSAPMS(pk,pv,pms,epms))
    #endif
    epms

//#begin-decrypt_int
let decrypt_int dk si cv cvCheck encPMS =
  (* Security measures described in RFC 5246, section 7.4.7.1 *)
  (* 1. Generate 46 random bytes, for fake PMS except client version *)
  let fakepms = random 46 in
  let expected = versionBytes cv in
  (* 2. Decrypt the message to recover plaintext *)
  match CoreACiphers.decrypt_pkcs1 (RSAKey.repr_of_rsaskey dk) encPMS with
    | Some pms when length pms = 48 ->
        let (clVB,postPMS) = split pms 2 in
        match si.protocol_version with
          | TLS_1p1 | TLS_1p2 ->
              (* 3. If new TLS version, just go on with client version and true pms.
                    This corresponds to a check of the client version number, but we'll fail later. *)
              expected @| postPMS
          
          | SSL_3p0 | TLS_1p0 ->
              (* 3. If check disabled, use client provided PMS, otherwise use our version number *)
              if cvCheck 
              then expected @| postPMS
              else pms
    | _  -> 
        (* 3. in case of decryption length error, continue with fake PMS *) 
        expected @| fakepms
//#end-decrypt_int

#if ideal
let rec pmsassoc (i:(RSAKey.pk * ProtocolVersion * bytes)) (pmss:((RSAKey.pk * ProtocolVersion * bytes) * CRE.rsapms) list) = 
    let (pk,pv,dummy_pms)=i in
    match pmss with 
    | [] -> None 
    | ((pk',pv',dummy_pms'),ideal_pms)::mss' when pk=pk' && pv=pv' && dummy_pms=dummy_pms' -> Some(ideal_pms) 
    | _::mss' -> pmsassoc i mss'
#endif

let decrypt (sk:RSAKey.sk) si cv check_client_version_in_pms_for_old_tls encPMS =
    match Cert.get_chain_public_encryption_key si.serverID with
    | Error(x,y)  -> unexpected (perror __SOURCE_FILE__ __LINE__ "The server identity should contain a valid certificate")
    | Correct(pk) ->
        let pmsb = decrypt_int sk si cv check_client_version_in_pms_for_old_tls encPMS in
        //#begin-ideal2
        #if ideal
        match pmsassoc (pk,cv,pmsb) !log with
          | Some(ideal_pms) -> ideal_pms
          | None            -> 
        #endif
            CRE.coerceRSA pk cv pmsb
        //#end-ideal2
        
