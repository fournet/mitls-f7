#! /usr/bin/env python

# --------------------------------------------------------------------
import sys, os, subprocess as sp

# --------------------------------------------------------------------
BIN = '../../Bench/bin/Debug/Bench.exe'

CONFIGS = [
    ('rsa.cert-01.mitls.org', 'TLS_RSA_WITH_RC4_128_MD5'),
    ('rsa.cert-01.mitls.org', 'TLS_RSA_WITH_RC4_128_SHA'),
    ('rsa.cert-01.mitls.org', 'TLS_RSA_WITH_3DES_EDE_CBC_SHA'),
    ('rsa.cert-01.mitls.org', 'TLS_RSA_WITH_AES_128_CBC_SHA'),
    ('rsa.cert-01.mitls.org', 'TLS_RSA_WITH_AES_128_CBC_SHA256'),
]

# --------------------------------------------------------------------
def _main():
    for config in CONFIGS:
        environ = os.environ.copy()
        environ['CIPHERSUITE'] = config[1]
        environ['CERTNAME']    = config[0]

        sp.check_call([BIN], env = environ)

# --------------------------------------------------------------------
if __name__ == '__main__':
    _main()
