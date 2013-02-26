#! /usr/bin/env python

# --------------------------------------------------------------------
import sys, os, re

# --------------------------------------------------------------------
NAMES = [
    ('TLS_RSA_WITH_RC4_128_MD5'           , ('RSA', 'RC4 / MD5')),
    ('TLS_RSA_WITH_RC4_128_SHA'           , ('RSA', 'RC4 / SHA')),
    ('TLS_RSA_WITH_3DES_EDE_CBC_SHA'      , ('RSA', '3DES / SHA')),
    ('TLS_RSA_WITH_AES_128_CBC_SHA'       , ('RSA', 'AES 128 / SHA')),
    ('TLS_RSA_WITH_AES_128_CBC_SHA256'    , ('RSA', 'AES 128 / SHA 256')),
    ('TLS_RSA_WITH_AES_256_CBC_SHA'       , ('RSA', 'AES 256 / SHA')),
    ('TLS_RSA_WITH_AES_256_CBC_SHA256'    , ('RSA', 'AES 256 / SHA 256')),
    ('TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA'  , ('DHE', '3DES / SHA')),
    ('TLS_DHE_DSS_WITH_AES_128_CBC_SHA'   , ('DHE', 'AES 128 / SHA')),
    ('TLS_DHE_DSS_WITH_AES_128_CBC_SHA256', ('DHE', 'AES 128 / SHA 256')),
    ('TLS_DHE_DSS_WITH_AES_256_CBC_SHA'   , ('DHE', 'AES 256 / SHA')),
    ('TLS_DHE_DSS_WITH_AES_256_CBC_SHA256', ('DHE', 'AES 256 / SHA 256')),
]

# --------------------------------------------------------------------
def _main():
    contents = [os.path.join('results', x + '.txt') \
                    for x in ('mitls', 'openssl', 'oracle-jsse-1.7')]
    contents = [(x, open(x, 'rb').read().splitlines()) for x in contents]

    result  = dict()
    ciphers = list()
    names   = list()

    for name, content in contents:
        name = os.path.splitext(os.path.basename(name))[0]
        names.append(name)
        for line in content:
            m1 = re.search('^(.*?): ((:?\d|\.)+) HS/s$' , line)
            m2 = re.search('^(.*?): ((:?\d|\.)+) MiB/s$', line)
            if m1 is not None:
                result.setdefault(name, {}).setdefault(m1.group(1), {})['HS'] = \
                    float(m1.group(2))
            if m2 is not None:
                result.setdefault(name, {}).setdefault(m2.group(1), {})['rate'] = \
                    float(m2.group(2))

    for cipher, name in NAMES:
        columns = [(' & '.join(name)).replace('_', '\\_')]
        for name in names:
            hs = result.get(name, {}).get(cipher, {}).get('HS'  , None) 
            bw = result.get(name, {}).get(cipher, {}).get('rate', None)
            columns.append(' - ' if hs is None else '%.2f' % (hs,))
            columns.append(' - ' if bw is None else '%.2f' % (bw,))
        print ' & '.join(columns) + '\\\\'

# --------------------------------------------------------------------
if __name__ == '__main__':
    _main()
