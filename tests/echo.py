#! /usr/bin/env python

# --------------------------------------------------------------------
import sys, os, re, subprocess as sp

# --------------------------------------------------------------------
CS_DEFAULT = 'TLS_RSA_WITH_AES_128_CBC_SHA'

OPENSSL_CIPHERS = {
    'TLS_RSA_WITH_NULL_MD5'           : 'NULL-MD5'     ,
    'TLS_RSA_WITH_NULL_SHA'           : 'NULL-SHA'     ,
    'TLS_RSA_WITH_NULL_SHA256'        : None           ,
    'TLS_RSA_WITH_RC4_128_MD5'        : 'RC4-MD5'      ,
    'TLS_RSA_WITH_RC4_128_SHA'        : 'RC4-SHA'      ,
    'TLS_RSA_WITH_3DES_EDE_CBC_SHA'   : 'DES-CBC3-SHA' ,
    'TLS_RSA_WITH_AES_128_CBC_SHA'    : 'AES128-SHA'   ,
    'TLS_RSA_WITH_AES_128_CBC_SHA256' : 'AES128-SHA256',
    'TLS_RSA_WITH_AES_256_CBC_SHA'    : 'AES256-SHA'   ,
    'TLS_RSA_WITH_AES_256_CBC_SHA256' : 'AES256-SHA256',
}

OPENSSL_VERSIONS = {
    'SSL_3p0': 'ssl3'  ,
    'TLS_1p0': 'tls1'  ,
    'TLS_1p1': 'tls1_1',
    'TLS_1p2': 'tls1_2',
}

class SSL_CLI(object):
    servercrt = ''
    clientcrt = ''
    crthashed = 'pki/db/ca.db.certs'
    cipher    = CS_DEFAULT
    address   = '127.0.0.1:6000'
    version   = ''

    def _build_openssl_common(self, args):
        args.append('-quiet')
        args.extend(['-CApath', self.crthashed])

        if self.version:
            args.append('-no_ssl2')

            if self.version not in OPENSSL_VERSIONS:
                raise ValueError('TLS version: %s' % (option.version,))
            args.append('-%s' % OPENSSL_VERSIONS[self.version])

        args.extend(['-cipher', OPENSSL_CIPHERS[self.cipher]])

    def _build_openssl_client(self, args):
        args.append('s_client')
        self._build_openssl_common(args)
        if self.clientcrt:
            args.extend(['-cert', self.clientcrt + '.crt'])
            args.extend(['-key' , self.clientcrt + '.key'])
        args.extend(['-connect', self.address])

    def _build_openssl_server(self, args):
        args.append('s_server')
        self._build_openssl_common(args)
        if self.servercrt:
            args.extend(['-cert', self.servercrt + '.crt'])
            args.extend(['-key' , self.servercrt + '.key'])
        args.extend(['-port', ''.join(self.address.split(':')[1:2])])

    def build(self, vendor, isclient):
        args, mth = [], '_build_%s_%s' % (vendor, 'client' if isclient else 'server')
        getattr(self, mth)(args); return args

    def run(self, vendor, isclient):
        cmd = [vendor] + self.build(vendor, isclient)
        # print >>sys.stderr, 'Command: %r' % (cmd,)
        os.execvp(cmd[0], cmd) or exit(127)

# --------------------------------------------------------------------
def _options():
    from optparse import OptionParser, Option

    parser = OptionParser()
    parser.add_option('', '--port'         , default='6000')
    parser.add_option('', '--address'      , default='127.0.0.1')
    parser.add_option('', '--ciphers'      , default=[CS_DEFAULT], action='append')
    parser.add_option('', '--client-name'  , default='')
    parser.add_option('', '--server-name'  , default='mitls.example.org')
    parser.add_option('', '--sessionDB-dir', default='sessionDB')
    parser.add_option('', '--tlsversion'   , default='TLS_1p0')
    parser.add_option('', '--client'       , default=False, action='store_true')

    (options, args) = parser.parse_args()

    if len(args):
        parser.error('this program does not take any argument')

    return options

# --------------------------------------------------------------------
def _openssl_version():
    try:
        process = sp.Popen(['openssl', 'version'], stdout=sp.PIPE)
        output  = process.communicate()[0]
        process.poll()
    except OSError:
        return None

    output = ''.join(output.splitlines()[:1])
    match  = re.search(r'^OpenSSL (\S+)', output)

    if match is None:
        return None

    version = match.group(1)
    match   = re.search('(.*?)([a-z]+)$', version)

    if match is not None:
        version = match.group(1)

    try:
        version = tuple(map(int, version.split('.')))
    except ValueError:
        return None

    return version + (0,) * max(0, 3 - len(version))

# --------------------------------------------------------------------
def _main():
    version = _openssl_version()

    if version is None or version < (1, 0, 1):
        print >>sys.stderr, 'invalid openssl version'
        exit (1)

    options = _options()

    builder = SSL_CLI()
    builder.cipher = options.ciphers[-1]
    if options.server_name:
        builder.servercrt = 'pki/certificates/%s' % (options.server_name)
    if options.client_name:
        builder.clientcrt = 'pki/certificates/%s' % (option.client_name)
    builder.address = '%s:%s' % (options.address, options.port)
    builder.version = options.tlsversion

    builder.run('openssl', options.client)

# --------------------------------------------------------------------
if __name__ == '__main__':
    _main()
