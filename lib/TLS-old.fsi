module TLS

open Bytes
open Error
open Dispatch
open TLSInfo
open Tcp
open DataStream

(* We can't buffer application data internally. They are blessed by the application
   using a specific SessionInfo i, and if we buffer them, we might send them
   under a different SessionInfo i'.
   We stick to the OpenSSL interface.
   Writing: Two options: (Note: OpenSSL offers only one function, whose behavior
    depends on the settings within the SSL context; we make this distinction explicit.)
    writeFully: take a user blessed buffer and does not return until all data have
                been sent. Returns the (number of) bytes that have been written.
                Errors: connection closed: returns the number of bytes
                that have been written; re-handshake: returns the bytes
                that have been written and the new SessionInfo.
    writeFragment: take a user blessed buffer and writes the first fragment on the
                network. Returns the (number of) bytes that have been written.
                Errors: like WriteFully.
  For writing, I expect two predicates: SendUpTo(), which indicates data blessed by
  the application (but that may not be sent) and is used as a precondition for the
  write* functions. And Sent(), which holds after a write* function returns, only on
  the data that have been actually sent.

  Reading:
    read: tries to read up to n bytes from the network. Returns the read bytes.
                Like OpenSSL, will read at most one Application Data fragment
                from the network. If a record has been received but not yet
                completely given to the application, no access to the TCP
                socket will be made, until the buffered fragment will be
                completely delivered (avoid mixing fragments of different
                sessions). The value n must be greater than 0.
                Errors: connection closed: returns the bytes read
                so far anyway; re-handshake: returns the bytes read under the previous
                SessionInfo, and returns the new SessionInfo.
  
  Write will always only write data to the network (note: this differs from OpenSSL,
  where write can also read data from the network) so that we don't get into
  "embarassing" situations, like filling the input buffer while writing, or
  getting a new SessionInfo, but still buffering read data under the previos
  SessionInfo.
  Read will both write and read data from the network.

  We assume the user will invoke read often enough so to avoid deadlocks. Read
  actually acts as the scheduler. Read is never "blocking":
  if data are not available on the socket, read will not wait for them,
  instead it will return zero bytes read.
  
  Note: ErrorCause must be extended to:
    | NewSessionInfo of Connection * bytes
    Where Connection is the new connection after re-handshake (and hence contains the
    new SessionInfo), and bytes are the bytes sent with the previous Connection
*)

(* Idealized computational-friendly interface *)
(*
type payload
function val size: payload -> int
(* we might need concat and split for the payload type *)
(* In fact, payload is an array (of something, of a known length). We will split/concat etc, but we won't look at the single <something> (bytes) *)

val write: Connection -> payload -> (payload Result) * Connection (* The returned payload is the amount of data *not* sent this time *)
val writeFully: Connection -> payload -> (unit Result) * Connection

val read: Connection -> int -> (payload Result) * Connection (* returns a payload which is up to "int" len *)
*)

(* OpenSSL like interface. Not good to deal with commitment on data *)
(*
val write: Connection -> bytes -> ((bytes * bytes) Result) * Connection
val writeFully: Connection -> bytes -> ((bytes * bytes) Result) * Connection
*)

(* Computationally-friendly interface. Ask the application to commit on certain data, that will
   be stored internally by the TLS library. The user can just ask to send the next fragment of committed data,
   or to block until all fragments are sent. *)
val write: Connection -> range -> delta -> Connection * (range * delta) option Result


(* val write_buffer_empty: Connection -> bool *)
(* In read and send/flush we return (x Result) * Connection, because an error could also be a notification, like MustRead or NewSessionInfo *)
(* val sendOneFragment: Connection -> (unit Result) * Connection *)
(* val flush: Connection -> (unit Result) * Connection *)

val read: Connection -> Connection * ((range * delta) Result) // This order, because returned bytes depend on returned connection
(* Polls whether there are data available in the current input buffer
   (a processed application data fragment not yet delivered to the user).
   Note that this function will not check whether data are available on the
   underlying socket, because it would not be useful in TLS (we might need
   to read more bytes than available to parse a full fragment anyway) *)
(* val dataAvailable: Connection -> bool *)

(* Complete SSL shutdown, with bi-directional Close_notify alerts,
   but does not close the underlying NetworkStream *)
val shutdown: Connection -> unit

(* Get SessionInfo from the current Connection. *)
val getSessionInfo: Connection -> SessionInfo

(* CLIENT SIDE *)

(* New Connection, new Session:
    Performs the first full handshake, and
    returns the new Connection (which will hold the new SessionInfo).
   We might allow some callback for server certificate chain validation,
   and for possible client certificate retrieval.
   Implementation note: in practice, we'll create a connection with null
   parameters, and will inovke read enough times to get the NewSessionInfo
   error. We will then forward the new, non-null connection to the user.
   Typechecking will ensure that if the connection is with null parameters,
   the read function always returns the empty_bstr.
*)
val connect: NetworkStream -> protocolOptions -> (unit Result) * Connection

(* New Connection, old(/new) Session:
    Tries to perform a resumption handshake. If the server accepts
    resumption, the SessionInfo in the returned Connection will match
    the given SessionInfo. If the server did not accept resumption,
    a full handshake will be performed, and a new SessionInfo returned.
    Implementation note: same as connect. Also note that protocolOptions
    should be "compatible" with the resumed session, but we have no way to
    enforce this at the moment.
*)
val resume: NetworkStream -> sessionID -> protocolOptions -> (unit Result) * Connection

(* Old Connection, new Session:
    Asks to start a new full handshake over the existing connection.
    Note that no data are sent or received when this function is invoked.
    Only an internal flag will be set (and possibly some output buffers of the
    hanshake protocol filled, but the user shall not be concerned about this),
    asking to re-handshake upon next read or write operation.
    In particular, the returned Connection will have the same SessionInfo of the
    given Connection, only the internal flags (and buffers) will be changed.
    Rationale: user data secured by the previous SessionInfo might still be
      recevied while performing the re-handshake. A safe and reliable way
      is to let the user read/write data normally, until a NewSessionInfo error
      will be returned by the read operation, notifying that a new session
      has been established. If the user wants to "block" until the handshake is
      finished, it has to keep reading until the NewSessionInfo error is received.
      All those reads are expected to return 0 bytes read, but nothing can prevent
      the other side to send application data during the rehandshake. Whether those
      data are acceptable is application specific, and must be handled in the
      application. Note that OpenSSL seems to differ, allowing the user to set
      a special flag:
        ssl->state = SSL_ST_ACCEPT;
      which will let the library issue an error if application data are received
      during the handshake. This feature is poorly documented, violates encapsulation,
      and if one forgets to set the flag then there is no way to know which data
      are sent/received before the handshake and which data are sent/received after.
*)
(* Note: for all re-handshake functions (rehandshake, rekey, handshakeRequest),
    it is easy to implement the blocking version (similar to accept/connect)
    that sets the flags and internally invokes read enough to get the NewSessionInfo
    error. In this case, if user data are received, the connection is closed.
    Note that all read that happen between a re-handshake function is invoked
    and the NewSessionInfo error is reported are not blocking, assuming the other
    side sends appropriate handshake packets. *)
val rehandshake: Connection -> protocolOptions -> Connection (* Only flag setting *)
val rehandshake_now: Connection -> protocolOptions -> (unit Result) * Connection (* Blocking until handshake terminates *)

(* Old Connection, old(/new) Session:
    Asks to start a resumption handshake over the existing connection,
    which is in fact re-keying.
    A full handshake will be performed if the server does not accept resumption.
    Like for the rehandshake function, no data will be sent/received, but only
    internal flags/buffers will be set. *)
val rekey: Connection -> protocolOptions -> Connection (* Only flag setting *)
val rekey_now: Connection -> protocolOptions -> (unit Result) * Connection (* Blocking until handshake terminates *)

(* Missing API: something like "re-resume":
   Old Connection, old(/new) Session, but the tentatively resumed session
   is not the current one. Probably not very useful, and the user might have
   problem in understanding how to use it anyway. But it might be
   useful to claim "complete" verification of different possible scenarios. *)

(* SERVER SIDE *)

(* New Connection, new/old Session:
    Waits (blocking call) for a new client to connect and start a handshake.
    If the client asks for session resumption (and server has that session
    in its cache), a short handshake will take place.
    Implementation note: same as connect.
    We have two variants:
     - one takes a TcpListener: it waits until a client connects, and then runs an handshake
     - one takes an already connected NetwrokStream, and directly runs an handshake *)
val accept: TcpListener -> protocolOptions -> (unit Result) * Connection
val accept_connected: NetworkStream -> protocolOptions -> (unit Result) * Connection

(* Old Connection, new/old Session:
    Sets an internal flag asking to send a Hello Request message on next
    read/write operation. If client will ask for resumption and the session
    to be resumed is cached, a resumption handshake will take place.
    Rationale: same as rehandshake.
*)
val handshakeRequest: Connection -> protocolOptions -> Connection (* Only flag setting *)
val handshakeRequest_now: Connection -> protocolOptions -> (unit Result) * Connection (* Blocking until handshake terminates *)
