#! /usr/bin/env python

# --------------------------------------------------------------------
import sys, os

# --------------------------------------------------------------------
OPENSSL_CIPHERS = {
    'TLS_RSA_WITH_RC4_128_SHA'        : 'RC4-SHA'      ,
    'TLS_RSA_WITH_3DES_EDE_CBC_SHA'   : 'DES-CBC3-SHA' ,
    'TLS_RSA_WITH_AES_128_CBC_SHA'    : 'AES128-SHA'   ,
    'TLS_RSA_WITH_AES_128_CBC_SHA256' : 'AES128-SHA256',
    'TLS_RSA_WITH_AES_256_CBC_SHA'    : 'AES256-SHA'   ,
    'TLS_RSA_WITH_AES_256_CBC_SHA256' : 'AES256-SHA256',
}

class SSLOptions(object):
    debug     = False
    servercrt = 'pki/certificates/cert-01.needham.inria.fr'
    clientcrt = 'pki/certificates/cert-02.needham.inria.fr'
    cacrt     = 'pki/certificates/ca.crt'
    crthashed = 'pki/db/ca.db.certs'
    cipher    = 'TLS_RSA_WITH_AES_128_CBC_SHA'
    address   = '127.0.0.1:6000'

    @classmethod
    def _build_openssl_common(cls, args):
        if cls.debug:
            args.append('-debug')
        args.extend(['-CAfile', cls.cacrt])
        args.extend(['-CApath', cls.crthashed])
        args.extend(['-tls1', '-no_ssl2', '-no_ssl3'])
        args.extend(['-cipher', OPENSSL_CIPHERS[cls.cipher]])

    @classmethod
    def _build_openssl_client(cls, args):
        args.append('s_client')
        cls._build_openssl_common(args)
        if cls.clientcrt is not None:
            args.extend(['-cert', cls.clientcrt + '.crt'])
            args.extend(['-key' , cls.clientcrt + '.key'])
        args.extend(['-connect', cls.address])

    @classmethod
    def _build_openssl_server(cls, args):
        args.append('s_server')
        cls._build_openssl_common(args)
        args.extend(['-cert', cls.servercrt + '.crt'])
        args.extend(['-key' , cls.servercrt + '.key'])
        args.extend(['-port', ''.join(cls.address.split(':')[1:2])])

    @classmethod
    def build(cls, vendor, isclient):
        args, mth = [], '_build_%s_%s' % (vendor, 'client' if isclient else 'server')
        cls.__dict__[mth].__get__(None, cls)(args)
        return args

    @classmethod
    def run(cls, vendor, isclient):
        cmd = [vendor] + cls.build(vendor, isclient)
        print >>sys.stderr, 'Command: %r' % (cmd,)
        os.execvp(cmd[0], cmd) or exit(127)

# --------------------------------------------------------------------
def _main():
    if sys.argv[1:2] == ['server']:
        SSLOptions.run(vendor = 'openssl', isclient = False)
    else:
        SSLOptions.run(vendor = 'openssl', isclient = True)

# --------------------------------------------------------------------
if __name__ == '__main__':
    _main()
