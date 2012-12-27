/* -------------------------------------------------------------------- */
#include <sys/types.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#include <errno.h>
#include <assert.h>

#ifndef WIN32
# include <unistd.h>
#endif

#ifdef WIN32
# include <winsock2.h>
# include <ws2tcpip.h>
#else
# include <sys/socket.h>
# include <netinet/in.h>
# include <netinet/tcp.h>
# include <arpa/inet.h>
# include <netdb.h>
#endif

#ifdef WIN32
# define SHUT_RD   SD_RECEIVE
# define SHUT_WR   SD_SEND
# define SHUT_RDWR SD_BOTH
#endif

#ifdef WIN32
#define ERR(e) WSA##e
#else
#define ERR(e) e
#endif

#include <log4c.h>

#include <event.h>
#include <event2/util.h>
#include <event2/listener.h>
#include <event2/bufferevent_ssl.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

/* -------------------------------------------------------------------- */
#define MAXBUF (1u << 17)       /* 128k */

/* -------------------------------------------------------------------- */
typedef struct sockaddr_in in4_t;

/* -------------------------------------------------------------------- */
typedef struct event event_t;
typedef struct event_base event_base_t;
typedef struct bufferevent bufferevent_t;
typedef struct evbuffer evbuffer_t;
typedef struct evconnlistener evconnlistener_t;

static event_base_t *evb = NULL;

/* -------------------------------------------------------------------- */
static const int zero = 0;
static const int one  = 1;

/* -------------------------------------------------------------------- */
void* xmalloc(size_t size) {
    void *p = malloc(size);

    if (p == NULL) {
        if (size == 0)
            return xmalloc(1u);
        abort();
    }
    return p;
}

void* xrealloc(void *p, size_t size) {
    void *newp = realloc(p, size);

    if (newp == NULL) {
        if (size == 0)
            return NULL;
        abort();
    }
    return newp;
}

void* xcalloc(size_t nmemb, size_t size) {
    void *p = calloc(nmemb, size);

    if (p == NULL)
        abort();
    return p;
}

/* -------------------------------------------------------------------- */
#ifdef WIN32
char *strndup(const char *s, size_t sz);

char *strndup(const char *s, size_t sz) {
    size_t  slen = strlen(s);
    char   *new  = NULL;

    slen = (slen > sz) ? sz : slen;
    new  = malloc (slen + 1);

    if (new == NULL)
        return NULL;

    memcpy(new, s, slen);
    new[slen] = '\0';

    return new;
}
#endif

char* xstrdup(const char *s) {
    if ((s = strdup(s)) == NULL)
        abort();
    return (char*) s;
}

char* xstrndup(const char *s, size_t n) {
    if ((s = strndup(s, n)) == NULL)
        abort();
    return (char*) s;
}

#define NEW(T, N) ((T*) xcalloc(N, sizeof(T)))

/* -------------------------------------------------------------------- */
log4c_category_t *logcat = NULL;

#define LOGPRIO (log4c_category_get_priority(logcat))

#define LOG_FATAL  LOG4C_PRIORITY_FATAL
#define LOG_ALERT  LOG4C_PRIORITY_ALERT
#define LOG_CRIT   LOG4C_PRIORITY_CRIT
#define LOG_ERROR  LOG4C_PRIORITY_ERROR
#define LOG_WARN   LOG4C_PRIORITY_WARN
#define LOG_NOTICE LOG4C_PRIORITY_NOTICE
#define LOG_INFO   LOG4C_PRIORITY_INFO
#define LOG_DEBUG  LOG4C_PRIORITY_DEBUG

static void elog(int level, const char *format, ...)
    __attribute__((format(printf, 2, 3)));

static void elog(int level, const char *format, ...) {
    va_list ap;

    if (level > log4c_category_get_priority(logcat))
        return ;

    va_start(ap, format);
    log4c_category_vlog(logcat, level, format, ap);
    va_end(ap);
}

static void _evlog(int severity, const char *msg) { /* event logger CB */
         if (severity == _EVENT_LOG_DEBUG) severity = LOG_DEBUG;
    else if (severity == _EVENT_LOG_MSG)   severity = LOG_NOTICE;
    else if (severity == _EVENT_LOG_WARN)  severity = LOG_WARN;
    else if (severity == _EVENT_LOG_ERR)   severity = LOG_ERROR;
    else severity = LOG4C_PRIORITY_UNKNOWN;

    log4c_category_log(logcat, severity, "%s", (char*) msg);
}

/* -------------------------------------------------------------------- */
static int _getaddr(in4_t *out, const char *addr) {
    char *hostname = NULL;
    char *service  = NULL;
    char *colon    = strrchr(addr, ':');

    int rr = 0;

    struct evutil_addrinfo ai, *res = NULL;

    if (colon == NULL) {
        hostname = xstrdup(addr);
        service  = xstrdup("https");
    } else {
        hostname = xstrndup(addr, colon - addr);
        service  = xstrdup(&colon[1]);
    }

    memset(&ai, 0, sizeof(ai));
    ai.ai_flags    = 0;
    ai.ai_family   = AF_INET;
    ai.ai_socktype = SOCK_STREAM;
    ai.ai_protocol = 0;

    if ((rr = evutil_getaddrinfo(hostname, service, &ai, &res)) != 0)
        goto bailout;

    assert(res[0].ai_addrlen == sizeof(in4_t));
    memcpy(out, res[0].ai_addr, sizeof(in4_t));

 bailout:
    free(hostname);
    free(service);

    if (res != NULL)
        evutil_freeaddrinfo(res);

    return rr;
}

/* -------------------------------------------------------------------- */
static char* inet4_ntop_x(const in4_t *addr) {
    char ip[] = "xxx.xxx.xxx.xxx";
    char *the = NULL;

    evutil_inet_ntop(AF_INET, &addr->sin_addr, ip, sizeof(ip));
    the = NEW(char, strlen(ip) + sizeof(uint16_t) * 8 + 1);
    sprintf(the, "%s:%d", ip, (uint16_t) ntohs(addr->sin_port));
    return the;
}

/* -------------------------------------------------------------------- */
typedef struct options {
    int   debug;
    in4_t echoname;
} options_t;

static void _options(options_t *options) {
    memset(options, 0, sizeof(options_t));

    options->debug = 1;

    options->echoname.sin_family      = AF_INET;
    options->echoname.sin_port        = htons(6000u);
    options->echoname.sin_addr.s_addr = INADDR_ANY;
}

/* -------------------------------------------------------------------- */
#define BEV_MOD_CB_READ  0x01
#define BEV_MOD_CB_WRITE 0x02
#define BEV_MOD_CB_ERROR 0x04

static void bufferevent_modcb(bufferevent_t *be, int flags,
                              bufferevent_data_cb readcb,
                              bufferevent_data_cb writecb,
                              bufferevent_event_cb errorcb,
                              void *cbarg)
{
    bufferevent_setcb
        (be, (flags & BEV_MOD_CB_READ ) ? readcb  : be->readcb ,
             (flags & BEV_MOD_CB_WRITE) ? writecb : be->writecb,
             (flags & BEV_MOD_CB_ERROR) ? errorcb : be->errorcb,
         cbarg);
}

/* -------------------------------------------------------------------- */
typedef struct stream {
    /* options ref. */
    const options_t *options;

    /* remote hand FD / bevent */
    int fd, rdclosed, wrclosed;
    bufferevent_t *bevent;

    /* SSL context */
    SSL *sslcontext;

    /* logger */
    char *addst, *adsrc;
} stream_t;

/* -------------------------------------------------------------------- */
#define stelog(S, L, F, ...) \
    elog(L, "%s <-> %s: " F, (S)->adsrc, (S)->addst, ## __VA_ARGS__)

#define S2C_LOG_ERROR(S) (stelog(S, LOG_ERROR, "S2C copy failure"))
#define C2S_LOG_ERROR(S) (stelog(S, LOG_ERROR, "C2S copy failure"))

/* -------------------------------------------------------------------- */
stream_t* stream_new(void) {
    stream_t *the = NEW(stream_t, 1);

    the->options    = NULL;
    the->rdclosed   = 0;
    the->wrclosed   = 0;
    the->fd         = -1;
    the->bevent     = NULL;
    the->sslcontext = NULL;
    the->addst      = NULL;
    the->adsrc      = NULL;

    return the;
}

void stream_free(stream_t *the) {
    if (the->adsrc) free(the->adsrc);
    if (the->addst) free(the->addst);

    if (the->bevent != NULL)
        bufferevent_free(the->bevent);
    (void) EVUTIL_CLOSESOCKET(the->fd);

    /* FIXME: SSL context */

    free(the);
}

/* -------------------------------------------------------------------- */
int _be_empty(bufferevent_t *be) {
    evbuffer_t *ibuffer = bufferevent_get_input (be);
    evbuffer_t *obuffer = bufferevent_get_output(be);

    return
        evbuffer_get_length(ibuffer) == 0 &&
        evbuffer_get_length(obuffer) == 0;
}

/* -------------------------------------------------------------------- */
int _check_for_stream_end(stream_t *stream) {
    if (stream->rdclosed && !stream->wrclosed) {
        evbuffer_t *output = bufferevent_get_output(stream->bevent);

        if (evbuffer_get_length(output) == 0) {
            (void) shutdown(stream->fd, SHUT_WR);
            stream->wrclosed = 1;
        }
    }

    if (!stream->wrclosed)
        return 0;

    stelog(stream, LOG_INFO, "all messages echo'ed. closing");
    stream_free(stream);

    return 1;
}

/* -------------------------------------------------------------------- */
void _onread(bufferevent_t *be, void *arg) {
    stream_t *stream = (stream_t*) arg;

    evbuffer_t *ibuffer = bufferevent_get_input (stream->bevent);
    evbuffer_t *obuffer = bufferevent_get_output(stream->bevent);

    (void) be;

    while (1) {
        size_t  len  = 0u;
        char   *line = evbuffer_readln(ibuffer, &len, EVBUFFER_EOL_CRLF);

        if (line == NULL)
            break ;
        (void) evbuffer_expand(obuffer, len+2);
        if (evbuffer_add(obuffer, line  , len) < 0 ||
            evbuffer_add(obuffer, "\r\n", 2  ) < 0)
        {
            C2S_LOG_ERROR(stream);
            goto bailout;
        }
    }

    return ;

 bailout:
    stelog(stream, LOG_ERROR, "closing connection");
    stream_free(stream);
}

/* -------------------------------------------------------------------- */
void _onwrite(bufferevent_t *be, void *arg) {
    stream_t *stream = (stream_t*) arg;

    (void) be;

    bufferevent_disable(stream->bevent, EV_WRITE);
    bufferevent_modcb(stream->bevent,
                      BEV_MOD_CB_READ | BEV_MOD_CB_WRITE,
                      NULL, NULL, NULL, stream);
    _check_for_stream_end(stream);
}

/* -------------------------------------------------------------------- */
void _onerror(bufferevent_t *be, short what, void *arg)  {
    stream_t *stream = (stream_t*) arg;

    (void) be;

    if ((what & BEV_EVENT_ERROR)) {
        int rr = evutil_socket_geterror(bufferevent_getfd(be));

        if (rr != ERR(ECONNRESET)) {
            stelog(stream, LOG_ERROR, "error client / server: %s", strerror(rr));
            goto bailout;
        }
    }

    if ((what & BEV_EVENT_EOF)) {
        evbuffer_t *ibuffer = bufferevent_get_input (stream->bevent);
        evbuffer_t *obuffer = bufferevent_get_output(stream->bevent);

        if (evbuffer_add_buffer(obuffer, ibuffer) < 0) {
            C2S_LOG_ERROR(stream);
            goto bailout;
        }

        (void) shutdown(stream->fd, SHUT_RD);
        stream->rdclosed = 1;

        if (!_check_for_stream_end(stream)) {
            bufferevent_modcb(stream->bevent,
                              BEV_MOD_CB_READ | BEV_MOD_CB_WRITE,
                              NULL, _onwrite, NULL, stream);
        }
    }

    return ;

 bailout:
    stelog(stream, LOG_ERROR, "closing connection");
    stream_free(stream);
}

/* -------------------------------------------------------------------- */
typedef struct bindctxt {
    /*-*/ SSL_CTX   *sslcontext;
    const options_t *options;
} bindctxt_t;

/* -------------------------------------------------------------------- */
void _onaccept(struct evconnlistener  *listener,
               /*--*/ evutil_socket_t  fd      ,
               struct sockaddr        *address ,
               /*--*/ int              socklen ,
               /*--*/ void            *arg     )
{
    bindctxt_t *context = (bindctxt_t*) arg;
    stream_t   *stream  = NULL;

    (void) listener;
    (void) socklen;

    stream = stream_new();

    stream->options = context->options;
    stream->fd      = fd;
    stream->adsrc   = inet4_ntop_x((in4_t*) address);
    stream->addst   = inet4_ntop_x(&context->options->echoname);

    evutil_make_socket_nonblocking(stream->fd);

    stelog(stream, LOG_INFO, "new client");

    if ((stream->sslcontext = SSL_new(context->sslcontext)) == NULL) {
        elog(LOG_ERROR, "cannot create SSL context");
        goto bailout;
    }

    stream->bevent =
        bufferevent_openssl_socket_new(evb, stream->fd, stream->sslcontext,
                                       BUFFEREVENT_SSL_ACCEPTING,
                                       BEV_OPT_DEFER_CALLBACKS);
    bufferevent_setcb(stream->bevent, _onread, NULL, _onerror, stream);
    bufferevent_enable(stream->bevent, EV_READ|EV_WRITE);

    return ;

 bailout:
    if (stream != NULL)
        stream_free(stream);
}


/* -------------------------------------------------------------------- */
static void _onaccept_error(struct evconnlistener *listener, void *ctxt) {
    int err = EVUTIL_SOCKET_ERROR();

    (void) listener;
    (void) ctxt;

    elog(LOG_FATAL, "got an error %d (%s) on the listener",
         err, evutil_socket_error_to_string(err));
    event_loopexit(NULL);
}

/* -------------------------------------------------------------------- */
static void _initialize_log4c(const options_t *options) {
    if (log4c_init() < 0 || (logcat = log4c_category_get("echo")) == NULL) {
        fprintf(stderr, "%s\n", "cannot initialize log4c");
        exit(EXIT_FAILURE);
    }

    log4c_category_set_priority(logcat, LOG_NOTICE);
    log4c_category_set_additivity(logcat, 0);

    {   log4c_appender_t *appender;

        if ((appender = log4c_appender_get("stderr")) != NULL)
            log4c_category_set_appender(logcat, appender);
    }

    if (options->debug)
        log4c_category_set_priority(logcat, LOG_DEBUG);
}

/* -------------------------------------------------------------------- */
#define MY_CERT "../pki/certificates/cert-01.needham.inria.fr.crt"
#define MY_KEY  "../pki/certificates/cert-01.needham.inria.fr.key"

static SSL_CTX* evssl_init(void) {
    SSL_CTX *context = NULL;

    SSL_load_error_strings();
    SSL_library_init();

    if (!RAND_poll()) {
        elog(LOG_FATAL, "cannot initialize entropy");
        goto bailout;
    }

    if ((context = SSL_CTX_new(TLSv1_server_method())) == NULL) {
        elog(LOG_FATAL, "cannot create SSL context");
        goto bailout;
    }

    if (!SSL_CTX_use_certificate_chain_file(context, MY_CERT)) {
        elog(LOG_FATAL, "cannot load certificate");
        goto bailout;
    }

    if (!SSL_CTX_use_PrivateKey_file(context, MY_KEY, SSL_FILETYPE_PEM)) {
        elog(LOG_FATAL, "cannot load certificate key");
        goto bailout;
    }

    return context;

 bailout:
    if (context != NULL)
        SSL_CTX_free(context);
    return NULL;
}

/* -------------------------------------------------------------------- */
int main(int argc, char *argv[]) {
    options_t         options;
    bindctxt_t        context;
    SSL_CTX          *sslcontext = NULL;
    evconnlistener_t *acceptln   = NULL;

    (void) argc;
    (void) argv;

    _options(&options);
    _initialize_log4c(&options);

    if ((sslcontext = evssl_init()) == NULL)
        return EXIT_FAILURE;

    memset(&context, 0, sizeof(context));
    context.options    = &options;
    context.sslcontext = sslcontext;

    if ((evb = event_init()) == NULL) {
        elog(LOG_FATAL, "cannot initialize libevent");
        return EXIT_FAILURE;
    }

    event_set_log_callback(_evlog);

    event_set_mem_functions(&xmalloc, &xrealloc, &free);

    acceptln = evconnlistener_new_bind
        (evb, _onaccept, &context,
         LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE, -1,
         (struct sockaddr*) &options.echoname, sizeof(options.echoname));

    if (acceptln == NULL) {
        elog(LOG_FATAL, "cannot create listener");
        return EXIT_FAILURE;
    }

    evconnlistener_set_error_cb(acceptln, _onaccept_error);

    elog(LOG_NOTICE, "started");

    event_dispatch();

    return 0;
}
