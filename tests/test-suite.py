#! /usr/bin/env python

# --------------------------------------------------------------------
import sys, os, time, socket, shutil, tempfile, subprocess as sp, logging
import lxml.etree as xml, cStringIO as sio

# --------------------------------------------------------------------
class Object(object):
    def __init__(self, **kw):
        self.__dict__.update(kw)

# --------------------------------------------------------------------
SCHEMA = '''\
<xsd:schema xmlns:xsd="http://www.w3.org/2001/XMLSchema">
  <xsd:element name="config" type="ConfigType"/>

  <xsd:complexType name="ConfigType">
    <xsd:sequence>
      <xsd:element name="bind"     type="xsd:string" />
      <xsd:element name="servname" type="xsd:string" />
      <xsd:element name="versions" type="xsd:string" />
      <xsd:element name="ciphers"  type="xsd:string" />
    </xsd:sequence>
  </xsd:complexType>
</xsd:schema>
'''

# --------------------------------------------------------------------
def _check_for_config(cr, sr, config):
    subpc, subps = None, None
    sessiondir   = None

    try:
        logging.debug('Creating empty session directory...')
        sessiondir = tempfile.mkdtemp()
        os.mkdir(os.path.join(sessiondir, 'client'))
        os.mkdir(os.path.join(sessiondir, 'server'))
        logfile = os.path.join(sessiondir, 'log')
        logging.debug('...created [%s/{client,server}]' % (sessiondir,))

        def build_command(refpgm, isclient):
            command  = ['./echo.py' if refpgm else '../bin/Echo.exe']
            command += ['--address'      , str(config.address[0]),
                        '--port'         , str(config.address[1]),
                        '--ciphers'      , config.cipher,
                        '--tlsversion'   , config.version,
                        '--server-name'  , config.servname,
                        '--sessionDB-dir', sessiondir]
            if not refpgm:
                if sys.platform.lower() not in ('cygwin', 'win32'):
                    command = ['mono', '--debug'] + command
            if isclient:
                command += ['--client']

            return command

        c_command = build_command(not cr, True )
        s_command = build_command(not sr, False)

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
            subpc = sp.Popen(c_command,
                             stdin  = sp.PIPE,
                             stdout = os.open(logfile, 
                                              os.O_WRONLY |
                                              os.O_CREAT  |
                                              os.O_TRUNC  ))
        except OSError, e:
            logging.error('Cannot start echo client: %s' % (e,))
            return False

        logging.debug('Waiting echo client to settle up...')
        time.sleep(1.5)

        logging.debug('Client <-> server communication...')

        DATA = 'dohj3do0aiF9eishilaiPh2aid2eidahch2eivaonevohmoovainazoo8Ooyoo9O'

        try:
            subpc.stdin.write('%s\r\n' % DATA)
            subpc.stdin.flush()
            time.sleep(0.5)
            subpc.stdin.close()
            time.sleep(0.5)
        except (IOError, OSError), e:
            logging.error('Error while interacting with server: %s' % (e,))
            return False

        contents = [x.strip() for x in open(logfile, 'r').readlines()]

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
def _main():
    logging.basicConfig(stream = sys.stderr,
                        level  = logging.DEBUG,
                        format = '%(asctime)-15s - %(levelname)s - %(message)s')

    schema = xml.XMLSchema(xml.parse(sio.StringIO(SCHEMA)))
    doc    = xml.parse(open('test-suite.xml', 'rb'))

    bind     = doc.xpath('/config/bind/text()')[0]
    servname = doc.xpath('/config/servname/text()')[0]
    versions = doc.xpath('/config/versions/text()')[0].split()
    ciphers  = doc.xpath('/config/ciphers/text()')[0].split()

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

    logging.info("Binding address is: `%s'" % ':'.join(map(str, bind)))

    nerrors = 0

    for cipher in ciphers:
        for version in versions:
            for (cr, sr) in [(False, True), (True, False), (True, True)]:
                logging.info("Checking for cipher: `%s'" % (cipher,))
                logging.info("* Client is miTLS: %r" % (cr,))
                logging.info("* Server is miTLS: %r" % (sr,))
                logging.info("* TLS version is : %s" % (version,))
    
                config = Object(cipher   = cipher,
                                version  = version,
                                address  = bind,
                                servname = servname)
                nerrors += int(not _check_for_config(cr, sr, config))

    logging.info('# errors: %d' % (nerrors,))
    exit(2 if nerrors else 0)

# --------------------------------------------------------------------
if __name__ == '__main__':
    _main()
