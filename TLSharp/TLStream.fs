module TLStream

open Bytes
open Tcp
open Error
open System
open System.IO

type TLSBehavior =
    | Client
    | Server

type TLStream(s:System.Net.Sockets.NetworkStream,b) =
    inherit Stream()
    let mutable buf:bytes = [||]
    let mutable conn =
       let tcpStream = Tcp.create s
       let (err,conn) =
           match b with
           | Client -> TLS.connect tcpStream AppCommon.defaultProtocolOptions
           | Server -> TLS.accept_connected tcpStream AppCommon.defaultProtocolOptions
       match err with
       | Error(x,y) -> raise (IOException(sprintf "Constructor: %A %A" x y))
       | Correct () -> conn

    override this.get_CanRead()     = true
    override this.get_CanWrite()    = true
    override this.get_CanSeek()     = false
    override this.get_Length()      = raise (NotSupportedException())
    override this.SetLength(i)      = raise (NotSupportedException())
    override this.get_Position()    = raise (NotSupportedException())
    override this.set_Position(i)   = raise (NotSupportedException())
    override this.Seek(i,o)         = raise (NotSupportedException())

    override this.Flush() =
        match TLS.flush conn with
        | (Error(x,y),c) -> raise (IOException(sprintf "Flush: %A %A" x y))
        | (Correct (),c) -> conn <- c

    override this.Read(buffer, offset, count) =
        let data =
            if equalBytes buf [||] then
                (* Read from the socket, and possibly buffer some data *)
                match TLS.read conn with
                | (Error(Tcp, Internal), _) -> [||] (* XXX: We should distinghuish between EOF and failures *)
                | (Error(x,y), c) -> raise (IOException(sprintf "Read %A %A" x y))
                | (Correct(data),c) ->
                    conn <- c
                    data
            else (* Use the buffer *)
                let tmp = buf in
                buf <- [||]
                tmp
        let l = length data in
        if l <= count then
            Array.blit data 0 buffer offset l
            l
        else
            let (recv,newBuf) = split data count in
            Array.blit recv 0 buffer offset count
            buf <- newBuf
            count

    override this.Write(buffer,offset,count) =
        let data = createBytes count 0 in
        Array.blit buffer offset data 0 count
        conn <- TLS.write conn data
        this.Flush()
