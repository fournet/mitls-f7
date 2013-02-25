#! /usr/bin/env python

# --------------------------------------------------------------------
import sys, os, subprocess as sp

# --------------------------------------------------------------------
BIN = '../../Bench/bin/Debug/Bench.exe'
# BIN = './openssl'
# BIN = 'java -cp jsse JSSE'

CONFIGS = [
    ('rsa', 'rsa.cert-01.mitls.org', 'TLS_RSA_WITH_RC4_128_MD5'           ),
    ('rsa', 'rsa.cert-01.mitls.org', 'TLS_RSA_WITH_RC4_128_SHA'           ),
    ('rsa', 'rsa.cert-01.mitls.org', 'TLS_RSA_WITH_3DES_EDE_CBC_SHA'      ),
    ('rsa', 'rsa.cert-01.mitls.org', 'TLS_RSA_WITH_AES_128_CBC_SHA'       ),
    ('rsa', 'rsa.cert-01.mitls.org', 'TLS_RSA_WITH_AES_128_CBC_SHA256'    ),
    ('rsa', 'rsa.cert-01.mitls.org', 'TLS_RSA_WITH_AES_256_CBC_SHA'       ),
    ('rsa', 'rsa.cert-01.mitls.org', 'TLS_RSA_WITH_AES_256_CBC_SHA256'    ),
    ('dsa', 'dsa.cert-01.mitls.org', 'TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA'  ),
    ('dsa', 'dsa.cert-01.mitls.org', 'TLS_DHE_DSS_WITH_AES_128_CBC_SHA'   ),
    ('dsa', 'dsa.cert-01.mitls.org', 'TLS_DHE_DSS_WITH_AES_128_CBC_SHA256'),
    ('dsa', 'dsa.cert-01.mitls.org', 'TLS_DHE_DSS_WITH_AES_256_CBC_SHA'   ),
    ('dsa', 'dsa.cert-01.mitls.org', 'TLS_DHE_DSS_WITH_AES_256_CBC_SHA256'),
]

# --------------------------------------------------------------------
def _main():
    for config in CONFIGS:
        environ = os.environ.copy()
        environ['PKI']         = '../pki/%s' % (config[0],)
        environ['CERTNAME']    = config[1]
        environ['CIPHERSUITE'] = config[2]

        sp.check_call(BIN, env = environ, shell = True)

# --------------------------------------------------------------------
if __name__ == '__main__':
    _main()
