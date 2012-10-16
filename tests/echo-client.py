#! /usr/bin/env python

# --------------------------------------------------------------------
import sys, os, socket, select

# --------------------------------------------------------------------
class SSLOptions(object):
    servercrt = 'pki/certificates/cert-02.needham.inria.fr'
    clientcrt = 'pki/certificates/cert-01.needham.inria.fr'
    cacrt     = 'pki/certificates/ca.crt'
    cipher    = 'TLS_RSA_WITH_RC4_128_SHA'
    address   = ('192.168.56.101', 6000)
    isclient  = True

# --------------------------------------------------------------------
class SSLException(Exception):
    pass

class SSLWantIO(SSLException):
    READ  = 0x01
    WRITE = 0x02
    X509  = 0x03

    def __init__(self, kind):
        self.kind = kind

class SSLZeroReturn(SSLException):
    pass

class SSLError(SSLException):
    def __init__(self, exn):
        SSLException.__init__(self, exn)

# --------------------------------------------------------------------
# OpenSSL

import OpenSSL.SSL as ossl

class OSSLTunnel(object):
    _CIPHERS = {
        'TLS_RSA_WITH_RC4_128_SHA'        : 'RC4-SHA'      ,
        'TLS_RSA_WITH_3DES_EDE_CBC_SHA'   : 'DES-CBC3-SHA' ,
        'TLS_RSA_WITH_AES_128_CBC_SHA'    : 'AES128-SHA'   ,
        'TLS_RSA_WITH_AES_128_CBC_SHA256' : 'AES128-SHA256',
        'TLS_RSA_WITH_AES_256_CBC_SHA'    : 'AES256-SHA'   ,
        'TLS_RSA_WITH_AES_256_CBC_SHA256' : 'AES256-SHA256',
    }

    def __init__(self, sock, opts):
        ctxt = ossl.Context(ossl.TLSv1_METHOD)
        ctxt.set_options(ossl.OP_NO_SSLv2 | ossl.OP_NO_SSLv3)
        if opts.clientcrt is not None:
            ctxt.use_certificate_file(opts.clientcrt + '.crt')
            ctxt.use_privatekey_file (opts.clientcrt + '.key')
        ctxt.set_cipher_list(self._CIPHERS[opts.cipher])
        ctxt.set_verify(ossl.VERIFY_PEER | ossl.VERIFY_FAIL_IF_NO_PEER_CERT,
                        lambda _conn, _x509, _eo, _ed, ok : ok)
        ctxt.load_verify_locations(opts.cacrt)

        self._conn = ossl.Connection(ctxt, sock)
        self._conn.setblocking(True)
        self._conn.set_connect_state()

    def _wrap_exn(self, e):
        if isinstance(e, ossl.WantReadError):
            return SSLWantIO(SSLWantIO.READ)
        if isinstance(e, ossl.WantWriteError):
            return SSLWantIO(SSLWantIO.WRITE)
        if isinstance(e, ossl.ZeroReturnError):
            return SSLZeroReturn()
        return SSLError(e)

    def _wrap_call(self, f):
        try:
            return f ()
        except ossl.Error, e:
            raise self._wrap_exn(e)

    def handshake(self):
        return self._wrap_call(lambda : self._conn.do_handshake())

    def shutdown(self):
        return self._wrap_call(lambda : self._conn.shutdown())

    def close(self):
        return self._wrap_call(lambda : self._conn.close())

    def recv(self, length):
        return self._wrap_call(lambda : self._conn.recv(length))

    def send(self, buf):
        return self._wrap_call(lambda : self._conn.send(buf))

# --------------------------------------------------------------------
# GnuTLS

import gnutls.connection as gssl
import gnutls.crypto     as gsslc
import gnutls.constants  as gsslct

class GSSLTunnel(object):
    _CIPHERS = {
        'TLS_RSA_WITH_AES_128_CBC_SHA' : (gsslct.KX_RSA, gsslct.MAC_SHA1, gsslct.CIPHER_AES_128_CBC),
    }

    def __init__(self, sock, opts):
        crt = gsslc.X509Certificate(open(opts.servercrt + '.crt').read())
        key = gsslc.X509PrivateKey (open(opts.servercrt + '.key').read())
        crd = gssl.X509Credentials(crt, key)

        crd.session_params.protocols    = (gsslct.PROTO_TLS1_0,)
        crd.session_params.compressions = (gsslct.COMP_NULL,)

        kx, mac, cs = self._CIPHERS[opts.cipher]

        crd.session_params.kx_algorithms  = (kx ,)
        crd.session_params.mac_algorithms = (mac,)
        crd.session_params.ciphers        = (cs ,)

        self._conn = gssl.ClientSession(sock, crd)
        self._conn.setblocking(True)

    def _wrap_call(self, f):
        return f()

    def handshake(self):
        return self._wrap_call(lambda : self._conn.handshake())

    def shutdown(self):
        try:
            self._wrap_call(lambda : self._conn.bye())
        except gssl.OperationWouldBlock:
            pass

    def close(self):
        return self._wrap_call(lambda : self._conn.close())

    def recv(self, length):
        return self._wrap_call(lambda : self._conn.recv(length))

    def send(self, buf):
        return self._wrap_call(lambda : self._conn.send(buf))

# --------------------------------------------------------------------
def _main():
    options = SSLOptions()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    sock.connect(options.address)
    sock = OSSLTunnel(sock, options)

    sock.handshake()
    sock.send('Hello World!\r\n')
    print sock.recv(65535).splitlines()
    sock.shutdown()
    sock.close()

# --------------------------------------------------------------------
if __name__ == '__main__':
    _main()
