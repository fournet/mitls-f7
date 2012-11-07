#! /usr/bin/env python

# --------------------------------------------------------------------
import sys, os, socket, subprocess as sp, logging
import lxml.etree as xml, cStringIO as sio

# --------------------------------------------------------------------
class Object(object):
    def __init__(self, **kw):
        self.__dict__.update(kw)

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
SCHEMA = '''\
<xsd:schema xmlns:xsd="http://www.w3.org/2001/XMLSchema">
  <xsd:element name="config" type="ConfigType"/>

  <xsd:complexType name="ConfigType">
    <xsd:sequence>
      <xsd:element name="driver"   type="xsd:string" />
      <xsd:element name="bind"     type="xsd:string" />
      <xsd:element name="servname" type="xsd:string" />
      <xsd:element name="ciphers"  type="xsd:string" />
    </xsd:sequence>
  </xsd:complexType>
</xsd:schema>
'''

DRIVERS = dict([('OpenSSL', OSSLTunnel)])

# --------------------------------------------------------------------
def _check_for_config(driver, config):
    subp = None

    try:
        command = ['EchoServer.exe',
                   '--bind-address', str(config.address[0]),
                   '--bind-port'   , str(config.address[1]),
                   '--cipher'      , config.cipher]

        logging.debug('Starting echo server [%s]' % (' '.join(command)))

        try:
            subp = sp.Popen(command)
        except OSError, e:
            logging.error('Cannot start echo server: %s' % (e,))
            return False

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
        sock.connect(options.address)
        sock = driver(sock, config)

        sock.handshake()
        sock.shutdown()
        sock.close()

    except (socket.error, SSLError), e:
        logging.error('I/O error: %s' % (e,))
        return False

    finally:
        if subp is not None:
            noexn(lambda : subp.kill())

# --------------------------------------------------------------------
def _main():
    logging.basicConfig(stream = sys.stderr,
                        level  = logging.DEBUG,
                        format = '%(asctime)-15s - %(levelname)s - %(message)s')

    schema = xml.XMLSchema(xml.parse(sio.StringIO(SCHEMA)))
    doc    = xml.parse(open('test-suite.xml', 'rb'))

    drivername = doc.xpath('/config/driver/text()')[0]
    bind       = doc.xpath('/config/bind/text()')[0]
    servname   = doc.xpath('/config/servname/text()')[0]
    ciphers    = doc.xpath('/config/ciphers/text()')[0].split()

    if ':' in bind:
        bind = tuple(bind.split(':', 1))
    else:
        bind = (bind, 6000)

    try:
        bind = \
            socket.getaddrinfo(bind[0], bind[1]  ,
                               socket.AF_INET    ,
                               socket.SOCK_STREAM,
                               socket.SOL_TCP    )[0][4]
    except socket.error, e:
        logging.fatal("cannot resolve `%s': %s" % (':'.join(bind), e))
        exit(1)

    if drivername not in DRIVERS:
        logging.fatal("unknown driver: `%s'" % (drivername,))
        exit(1)

    driver = DRIVERS[drivername]

    logging.info("Binding address is: `%s'" % ':'.join(map(str, bind)))
    logging.info("Driver is: `%s'" % (drivername,))

    nerrors = 0

    for cipher in ciphers:
        logging.info("Checking for cipher: `%s'" % (cipher,))

        config = Object(cacrt   = 'pki/certificates/ca.crt',
                        cipher  = cipher,
                        address = bind)
        nerrors += int(not _check_for_config(driver, config))

    logging.info('# errors: %d' % (nerrors,))
    exit(2 if nerrors else 0)

# --------------------------------------------------------------------
if __name__ == '__main__':
    _main()
