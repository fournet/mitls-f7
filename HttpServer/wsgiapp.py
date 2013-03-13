# ------------------------------------------------------------------------
class BaseApplication(object):
    @staticmethod
    def create():
        def application(environ, start_response):
            start_response("200 OK", [])
            return ['Hello World!']
        return application

# ------------------------------------------------------------------------
class miTLSApplication(object):
    @staticmethod
    def create():
        FRAMEWORK = 'C:/pyramid/Scripts/activate_this.py'
        execfile(FRAMEWORK, dict(__file__ = FRAMEWORK))

        import sys, os, mitls, pyramid.paster as paster

        basedir = os.path.join(os.path.dirname(mitls.__file__), os.path.pardir)
        basedir = os.path.normpath(basedir)
        inifile = os.path.join(basedir, 'development.ini')
        env     = paster.bootstrap(inifile)

        return env['app']

# ------------------------------------------------------------------------
main = miTLSApplication.create
