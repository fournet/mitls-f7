/* -------------------------------------------------------------------- */
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

#include "echo-log.h"
#include "echo-memory.h"
#include "echo-ssl.h"
#include "echo-net.h"
#include "echo-options.h"

/* -------------------------------------------------------------------- */
enum {
    OPT_PORT   ,
    OPT_ADDRESS,
    OPT_CIPHERS,
    OPT_CNAME  ,
    OPT_SNAME  ,
    OPT_DBDIR  ,
    OPT_TLSVER ,
    OPT_PKI    ,
    OPT_CLIENT ,
};


static const struct option long_options[] = {
    {"port"         , required_argument, 0, OPT_PORT   },
    {"address"      , required_argument, 0, OPT_ADDRESS},
    {"ciphers"      , required_argument, 0, OPT_CIPHERS},
    {"client-name"  , required_argument, 0, OPT_CNAME  },
    {"server-name"  , required_argument, 0, OPT_SNAME  },
    {"sessionDB-dir", required_argument, 0, OPT_DBDIR  },
    {"tlsversion"   , required_argument, 0, OPT_TLSVER },
    {"pki"          , required_argument, 0, OPT_PKI    },
    {"client"       , no_argument      , 0, OPT_CLIENT },
    {NULL           , 0                , 0, 0          },
};

/* -------------------------------------------------------------------- */
int _options(int argc, char *argv[], options_t *options) {
    const char     *address = "127.0.0.1";
    const char     *port    = "6000";
    const char     *ciphers = NULL;
    const char     *cname   = NULL;
    const char     *sname   = NULL;
    const char     *dbdir   = "sessionDB";
    const char     *pki     = "pki";
    /*-*/ tlsver_t  tlsver  = TLS_1p0;
    /*-*/ int       client  = 0;

    while (1) {
        int i = 0;
        int c = getopt_long(argc, argv, "", long_options, &i);

        if (c < 0)
            break ;

        switch (i) {
        case OPT_PORT   : port    = optarg; break ;
        case OPT_ADDRESS: address = optarg; break ;
        case OPT_CIPHERS: ciphers = optarg; break ;
        case OPT_CNAME  : cname   = optarg; break ;
        case OPT_SNAME  : sname   = optarg; break ;
        case OPT_DBDIR  : dbdir   = optarg; break ;
        case OPT_PKI    : pki     = optarg; break ;

        case OPT_TLSVER:
            tlsver = tlsver_of_name(optarg);
            if ((int) tlsver == -1) {
                elog(LOG_FATAL, "invalid TLS version: %s", optarg);
                return -1;
            }
            break ;

        default:
            abort();
        }
    }

    memset(options, 0, sizeof(options_t));

    options->debug = 1;

    if (getaddr4(&options->echoname, address, port) != 0) {
        elog(LOG_FATAL, "cannot resolve address %s:%s", address, port);
        return -1;
    }

    if (cname != NULL)
        options->cname = xstrdup(cname);
    if (sname != NULL)
        options->sname = xstrdup(sname);
    if (ciphers != NULL)
        options->ciphers = xstrdup(ciphers);

    options->client = client;
    options->tlsver = tlsver;
    options->dbdir  = xstrdup(dbdir);
    options->pki    = xstrdup(pki);

    if (options->sname == NULL) {
        elog(LOG_FATAL, "no server name given (--server-name)");
        return -1;
    }

    return 0;
}
