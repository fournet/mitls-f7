#! /usr/bin/env python

# --------------------------------------------------------------------
import sys, os, re

# --------------------------------------------------------------------
NAMES = dict(
    TLS_RSA_WITH_RC4_128_MD5            = 'RSA with RC4 / MD5',
    TLS_RSA_WITH_RC4_128_SHA            = 'RSA with RC4 / SHA',
    TLS_RSA_WITH_3DES_EDE_CBC_SHA       = 'RSA with 3DES / SHA',
    TLS_RSA_WITH_AES_128_CBC_SHA        = 'RSA with AES 128 / SHA',
    TLS_RSA_WITH_AES_128_CBC_SHA256     = 'RSA with AES 128 / SHA 256',
    TLS_RSA_WITH_AES_256_CBC_SHA        = 'RSA with AES 256 / SHA',
    TLS_RSA_WITH_AES_256_CBC_SHA256     = 'RSA with AES 256 / SHA 256',
    TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA   = 'DH-E with 3DES / SHA',
    TLS_DHE_DSS_WITH_AES_128_CBC_SHA    = 'DH-E with AES 128 / SHA',
    TLS_DHE_DSS_WITH_AES_128_CBC_SHA256 = 'DH-E with AES 128 / SHA 256',
    TLS_DHE_DSS_WITH_AES_256_CBC_SHA    = 'DH-E with AES 256 / SHA',
    TLS_DHE_DSS_WITH_AES_256_CBC_SHA256 = 'DH-E with AES 256 / SHA 256',
)

# --------------------------------------------------------------------
def _main():
    contents = sys.argv[1:]
    contents = [(x, open(x, 'rb').read().splitlines()) for x in contents]

    result  = dict()
    ciphers = list()
    names   = list()

    for name, content in contents:
        name = os.path.splitext(os.path.basename(name))[0]
        names.append(name)
        for line in content:
            m = re.search('^(.*?): ((:?\d|\.)+) HS/s$', line)
            if m is not None:
                result.setdefault(name, {})[m.group(1)] = \
                    float(m.group(2))
                if m.group(1) not in ciphers:
                    ciphers.append(m.group(1))

    for cipher in ciphers:
        columns = [NAMES[cipher].replace('_', '\\_')]
        for name in names:
            bw = result.get(name, {}).get(cipher, None)
            columns.append('-' if bw is None else '%.2f HS/s' % (bw,))
        print ' & '.join(columns) + '\\\\'

# --------------------------------------------------------------------
if __name__ == '__main__':
    _main()
