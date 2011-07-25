module PrintSessionDB

let _ =
    let storedIDs = SessionDB.getAllStoredIDs AppCommon.defaultProtocolOptions in
    printf "%A" storedIDs
    System.Console.ReadLine ()