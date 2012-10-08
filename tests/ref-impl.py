#! /usr/bin/env python

# --------------------------------------------------------------------
import sys, os, re, select, socket, threading, cStringIO as StringIO
import OpenSSL.SSL as ssl

# --------------------------------------------------------------------
CA_PEM_CRT_FILE = 'pki/certificates/ca.crt'

SERVER_PEM_KEY_FILE = 'pki/certificates/cert1.needham.inria.fr.key'
SERVER_PEM_CRT_FILE = 'pki/certificates/cert1.needham.inria.fr.crt'

CLIENT_PEM_KEY_FILE = 'pki/certificates/cert2.needham.inria.fr.key'
CLIENT_PEM_CRT_FILE = 'pki/certificates/cert2.needham.inria.fr.crt'

SERVER_INET_ADDR = ('127.0.0.1', 6000)

# --------------------------------------------------------------------
CIPHERS = {
    'TLS_RSA_WITH_RC4_128_SHA'        : 'RC4-SHA'      ,
    'TLS_RSA_WITH_3DES_EDE_CBC_SHA'   : 'DES-CBC3-SHA' ,
    'TLS_RSA_WITH_AES_128_CBC_SHA'    : 'AES128-SHA'   ,
    'TLS_RSA_WITH_AES_128_CBC_SHA256' : 'AES128-SHA256',
    'TLS_RSA_WITH_AES_256_CBC_SHA'    : 'AES256-SHA'   ,
    'TLS_RSA_WITH_AES_256_CBC_SHA256' : 'AES256-SHA256',
}

# --------------------------------------------------------------------
def _create_ctxt(cs, isclient):
    ctxt = ssl.Context(ssl.TLSv1_METHOD)
    ctxt.set_options(ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3)

    if isclient:
        ctxt.use_certificate_file(CLIENT_PEM_CRT_FILE, ssl.FILETYPE_PEM)
        ctxt.use_privatekey_file (CLIENT_PEM_KEY_FILE, ssl.FILETYPE_PEM)
    else:
        ctxt.use_certificate_file(SERVER_PEM_CRT_FILE, ssl.FILETYPE_PEM)
        ctxt.use_privatekey_file (SERVER_PEM_KEY_FILE, ssl.FILETYPE_PEM)

    ctxt.set_cipher_list(CIPHERS[cs])

    def _verify_x509(_c, x509, _eo, _ed, ok):
        # print >>sys.stderr, x509.get_subject().get_components()
        return ok

    ctxt.set_verify(ssl.VERIFY_PEER | ssl.VERIFY_FAIL_IF_NO_PEER_CERT, _verify_x509)
    ctxt.load_verify_locations(CA_PEM_CRT_FILE)

    return ctxt

# --------------------------------------------------------------------
def _server(cs):
    ctxt = _create_ctxt(cs, isclient = False)
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    conn = ssl.Connection(ctxt, conn)

    conn.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    conn.bind(SERVER_INET_ADDR)
    conn.listen(5)

    def _handle_client(client, peername):
        def _handler():
            print >>sys.stderr, "[%5s] %r" % ('new', peername,)

            try:
                client.do_handshake()
                client.setblocking(False)
    
                brecv, bsend, clientoff = '', '', False
    
                while True:
                    if len(bsend) == 0 and clientoff:
                        break
    
                    while len(brecv):
                        m = re.search('^(.*?)\r?\n', brecv)
                        if m is None:
                            if client.pending():
                                brecv += client.read(client.pending())
                                continue
                            else:
                                if clientoff:
                                    bsend += '%s\r\n' % (brecv,)
                                    brecv  = ''
                        else:
                            bsend += '%s\r\n' % (m.group(1),)
                            brecv  = brecv[len(m.group(0)):]
    
                    rfds = [client] if not clientoff else []
                    wfds = [client] if bsend else []
    
                    r, w, e = select.select(rfds, wfds, [])
    
                    def _r_0(x):
                        if len(x) == 0:
                            raise ssl.ZeroReturnError
                        return x
    
                    if client in r:
                        try:
                            while True:
                                try:
                                    brecv += _r_0(client.recv(65535))
                                except (ssl.WantReadError, ssl.WantWriteError), e:
                                    if isinstance(e, ssl.WantReadError):
                                        select.select([client], [], [])
                                    if isinstance(e, ssl.WantWriteError):
                                        select.select([], [client], [])
                                else:
                                    break
                        except ssl.ZeroReturnError:
                            clientoff = True
    
                    if client in w and len(bsend):
                        while True:
                            try:
                                bsend = bsend[client.send(bsend):]
                            except (ssl.WantReadError, ssl.WantWriteError), e:
                                if isinstance(e, ssl.WantReadError):
                                    select.select([client], [], [])
                                if isinstance(e, ssl.WantWriteError):
                                    select.select([], [client], [])
                            else:
                                break
    
                client.shutdown()
                client.close()
            finally:
                print >>sys.stderr, "[%5s] %r" % ('done', peername,)

        thr = threading.Thread(target = _handler)
        thr.setDaemon(True)
        thr.start()

    while True:
        _handle_client(*conn.accept())

# --------------------------------------------------------------------
def _client(cs):
    ctxt = _create_ctxt(cs, isclient = True)
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    conn = ssl.Connection(ctxt, conn)

    conn.connect(SERVER_INET_ADDR)
    conn.setblocking(True)
    conn.do_handshake()

    def _drain():
        aout = StringIO.StringIO()
        try:
            while True:
                aout.write(conn.read(65535))
        except ssl.ZeroReturnError:
            return aout.getvalue()

    conn.sendall('Hello World!\n')
    conn.shutdown()

    print _drain().splitlines()

    conn.close()

# --------------------------------------------------------------------
def _main(*args):
    def _usage_and_exit():
        print >>sys.stderr, 'Usage: %s <cipher> [%s]' % (args[0], '|'.join(entries))
        print >>sys.stderr
        for cs in sorted(CIPHERS.keys()):
            print >>sys.stderr, 'Ciphers: %s' % (cs,)
        exit(1)

    entries = ('server', 'client')

    if len(args)-1 != 2:
        _usage_and_exit()

    cipher = args[1]
    mode   = args[2]

    if mode not in ('server', 'client'):
        _usage_and_exit()
    if cipher not in CIPHERS.keys():
        _usage_and_exit()

    globals()['_%s' % (mode,)](cs = cipher)

# --------------------------------------------------------------------
if __name__ == '__main__':
    _main(*sys.argv)
