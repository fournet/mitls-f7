module FlexApps.UnitTests

open NLog

open TLSConstants

open FlexTLS
open FlexTypes

open FlexApps
open Parsing
open Attack_Alert
open Attack_FragmentClientHello
open Attack_EarlyCCS
open Attack_EarlyResume
open Attack_JavaLateCCS
open Attack_TripleHandshake
open Attack_SmallSubgroup_DHE
open Handshake_full_RSA
open Handshake_full_alert_RSA
open Handshake_full_DHE
open Handshake_resumption
open Handshake_tls13
open Metrics_DHE
open TraceInterpreter




type UnitTests = 
    class

    static member runAll () : unit =
        
        // Client Side Scenarios
        let _  = Handshake_full_RSA.client_with_auth("localhost","rsa.cert-02.mitls.org",4433) in
        let st = Handshake_full_RSA.client("localhost",4433) in
        let _  = Tcp.close st.ns in 
        let _  = Handshake_resumption.client(st,"localhost",4433) in
        let _  = Handshake_full_RSA.client("localhost",4433,st) in
        let _  = Handshake_full_DHE.client_with_auth("localhost","rsa.cert-02.mitls.org",4433) in
        let _  = Handshake_full_DHE.client("localhost",4433) in

        // Server Side Scenarios
        let _  = Handshake_full_RSA.server_with_client_auth("localhost","rsa.cert-01.mitls.org",4433) in
        let _  = Handshake_full_RSA.server("localhost","rsa.cert-01.mitls.org",4433) in
        let _  = Handshake_full_DHE.server_with_client_auth("localhost","rsa.cert-01.mitls.org",4433) in
        let _  = Handshake_full_DHE.server("localhost","rsa.cert-01.mitls.org",4433) in

        // Trace Interpreter
        let _ = TraceInterpreter.runClients "localhost" 4433 "rsa.cert-01.mitls.org" true in
        let _ = TraceInterpreter.runClients "localhost" 4433 "rsa.cert-01.mitls.org" false in
        let _ = TraceInterpreter.runServers 4433 "rsa.cert-01.mitls.org" true in
        let _ = TraceInterpreter.runServers 4433 "rsa.cert-01.mitls.org" false in

        // Attacks
        let _ = Attack_Alert.run("localhost", 4433) in
        let _ = Handshake_full_alert_RSA.client("localhost", 4433) in
        let _ = Attack_FragmentClientHello.run("localhost",fp=All(5)) in
        let _ = Attack_EarlyCCS.runMITM("localhost","localhost",6433,4433) in
        let _ = LateCCS.server("localhost",4433) in
        let _ = Attack_TripleHandshake.runMITM("localhost","rsa.cert-01.mitls.org",6433,"localhost",4433) in
        let _ = Attack_SmallSubgroup_DHE.run(true, 223,
                    "124325339146889384540494091085456630009856882741872806181731279018491820800119460022367403769795008250021191767583423221479185609066059226301250167164084041279837566626881119772675984258163062926954046545485368458404445166682380071370274810671501916789361956272226105723317679562001235501455748016154805420913",
                    "223","localhost")
        let _ = Attack_EarlyResume.run("localhost","rsa.cert-01.mitls.org",4433) in
        ()

    end