#! /usr/bin/env python

# --------------------------------------------------------------------
import sys, os, time, socket, subprocess as sp, logging
import ConfigParser as cp, StringIO as sio, shutil, tempfile

# --------------------------------------------------------------------
class Object(object):
    def __init__(self, **kw):
        self.__dict__.update(kw)

# --------------------------------------------------------------------
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

# --------------------------------------------------------------------
class MI_MI_TLS(object):
    miserver = True
    miclient = True

class MI_C_TLS(object):
    miserver = False
    miclient = True

# --------------------------------------------------------------------
def cygpath(mode, path):
    command = ['cygpath', '-%s' % (mode,), path]
    subp    = sp.Popen(command, stdout = sp.PIPE)
    return subp.communicate()[0].splitlines()[0]

# --------------------------------------------------------------------
def _check_for_config(mode, config):
    assert mode.miclient        # Non miTLS client unsupported

    subpc, subps = None, None
    sessiondir   = None

    try:
        logging.debug('Creating empty session directory...')
        sessiondir = tempfile.mkdtemp()
        os.mkdir(os.path.join(sessiondir, 'client'))
        os.mkdir(os.path.join(sessiondir, 'server'))
        logging.debug('...created [%s/{client,server}]' % (sessiondir,))

        def build_command(mivendor, isclient):
            assert not (not mivendor and isclient)

            mysessiondir = os.path.join(sessiondir, 'client' if isclient else 'server')
            win32        = sys.platform.lower() in ('cygwin', 'win32')
            cipher       = config.cipher

            if win32 and sys.platform.lower() == 'cygwin':
                mysessiondir = cygpath('w', mysessiondir)

            if not mivendor:
                cipher = OPENSSL_CIPHERS[cipher]

            if mivendor:
                pgm = '../bin/Echo.exe'
            else:
                pgm = 'i686-pc-mingw32-echo.exe' if win32 else 'echo'
                pgm = os.path.join('c-stub', pgm)

            command  = [pgm]
            command += ['--address'      , str(config.address[0]),
                        '--port'         , str(config.address[1]),
                        '--ciphers'      , cipher,
                        '--tlsversion'   , config.version,
                        '--server-name'  , config.servname,
                        '--sessionDB-dir', mysessiondir]

            if not mivendor:
                command += ['--pki', 'pki']

            if mivendor and not win32:
                command = ['mono', '--debug'] + command

            if isclient:
                command += ['--client']

            return command

        c_command = build_command(mode.miclient, True )
        s_command = build_command(mode.miserver, False)

        logging.debug('Starting echo server [%s]' % (' '.join(s_command)))

        try:
            subps = sp.Popen(s_command)
        except OSError, e:
            logging.error('Cannot start echo server: %s' % (e,))
            return False

	logging.debug('Waiting echo server to settle up...')
	time.sleep(1.5)

        logging.debug('Starting echo client [%s]' % (' '.join(c_command)))

        try:
            subpc = sp.Popen(c_command, stdin = sp.PIPE, stdout = sp.PIPE)
        except OSError, e:
            logging.error('Cannot start echo client: %s' % (e,))
            return False

        logging.debug('Waiting echo client to settle up...')
        time.sleep(1.5)

        logging.debug('Client <-> server communication...')

        DATA = 'dohj3do0aiF9eishilaiPh2aid2eidahch2eivaonevohmoovainazoo8Ooyoo9O'

        try:
            contents = subpc.communicate(DATA)[0].splitlines()
        except (IOError, OSError), e:
            logging.error('Error while interacting with server: %s' % (e,))
            return False

        return DATA in contents

    finally:
        for subp, who in [(subpc, 'client'), (subps, 'server')]:
            if subp is not None:
                logging.debug('Waiting echo %s to shutdown...' % (who,))
                time.sleep(.2)
                try: subp.kill()
                except OSError: pass
                
        if sessiondir is not None:
            shutil.rmtree(sessiondir, ignore_errors = True)

    logging.info('Test successful')
    return True

# --------------------------------------------------------------------
DEFAULTS = '''\
[config]
bind     = 127.0.0.1:6000
servname = cert-01.mitls.org
versions = TLS_1p0
ciphers  =  TLS_RSA_WITH_AES_128_CBC_SHA256
ciphers  =  TLS_RSA_WITH_AES_256_CBC_SHA256
'''

def _main():
    logging.basicConfig(stream = sys.stderr,
                        level  = logging.DEBUG,
                        format = '%(asctime)-15s - %(levelname)s - %(message)s')

    parser = cp.ConfigParser()
    parser.readfp(sio.StringIO(DEFAULTS))
    if not parser.read('test-suite.ini'):
        print >>sys.stderr, 'Cannot read configuration file'
        exit(1)

    bind     = parser.get('config', 'bind')
    servname = parser.get('config', 'servname')
    versions = parser.get('config', 'versions').split()
    ciphers  = parser.get('config', 'ciphers').split()

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

    logging.info("Binding address is: %s" % ':'.join(map(str, bind)))
    logging.info("Testing versions  : %s" % ', '.join(versions))
    logging.info("Testing ciphers   : %s" % ', '.join(ciphers))

    nerrors = 0

    for cipher in ciphers:
        for version in versions:
            for mode in (MI_C_TLS, MI_MI_TLS):
                logging.info("Checking for cipher: `%s'" % (cipher,))
                logging.info("* Client is miTLS: %r" % (mode.miclient,))
                logging.info("* Server is miTLS: %r" % (mode.miserver,))
                logging.info("* TLS version is : %s" % (version,))
    
                config = Object(cipher   = cipher,
                                version  = version,
                                address  = bind,
                                servname = servname)

                success  = _check_for_config(mode, config)
                nerrors += int(not success)

                if not success:
                    logging.error('---------- FAILURE ----------')

    logging.info('# errors: %d' % (nerrors,))
    exit(2 if nerrors else 0)

# --------------------------------------------------------------------
if __name__ == '__main__':
    _main()
