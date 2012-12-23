/* -------------------------------------------------------------------- */
#include <sys/types.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#include <errno.h>
#include <assert.h>

#include <fcntl.h>
#include <unistd.h>

#include <sys/time.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include <netdb.h>

#include <endian.h>

#include <log4c.h>

#include <event.h>
#include <event2/bufferevent_struct.h> /* Break abstraction */

#ifndef SOL_TCP
# define SOL_TCP IPPROTO_TCP
#endif

/* -------------------------------------------------------------------- */
#define MAXBUF (1u << 17)       /* 128k */

/* -------------------------------------------------------------------- */
typedef struct sockaddr_in in4_t;

/* -------------------------------------------------------------------- */
typedef struct event event_t;
typedef struct event_base event_base_t;
typedef struct bufferevent bufferevent_t;
typedef struct evbuffer evbuffer_t;

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
void tvdiff(/*-*/ struct timeval *tv ,
            const struct timeval *tv1,
            const struct timeval *tv2)
{
    tv->tv_sec  = tv1->tv_sec  - tv2->tv_sec ;
    tv->tv_usec = tv1->tv_usec - tv2->tv_usec;

    if (tv->tv_usec < 0) {
        tv->tv_sec  -= 1;
        tv->tv_usec += 1000000;
    }
}


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
int _getaddr(in4_t *out, const char *addr) {
    char *hostname = NULL;
    char *service  = NULL;
    char *colon    = strrchr(addr, ':');

    int rr = 0;

    struct addrinfo ai, *res = NULL;

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

    if ((rr = getaddrinfo(hostname, service, &ai, &res)) != 0)
        goto bailout;

    assert(res[0].ai_addrlen == sizeof(in4_t));
    memcpy(out, res[0].ai_addr, sizeof(in4_t));

 bailout:
    free(hostname);
    free(service);

    if (res != NULL)
        freeaddrinfo(res);

    return rr;
}

/* -------------------------------------------------------------------- */
char* inet4_ntop_x(const in4_t *addr) {
    char ip[] = "xxx.xxx.xxx.xxx";
    char *the = NULL;

    inet_ntop(AF_INET, &addr->sin_addr, ip, sizeof(ip));
    the = NEW(char, strlen(ip) + sizeof(uint16_t) * 8 + 1);
    sprintf(the, "%s:%d", ip, (uint16_t) ntohs(addr->sin_port));
    return the;
}

/* -------------------------------------------------------------------- */
typedef struct options {
    int   debug;
    in4_t echoname;
} options_t;

void _options(options_t *options) {
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

void bufferevent_modcb(bufferevent_t *be, int flags,
                       bufferevent_data_cb readcb,
                       bufferevent_data_cb writecb,
                       bufferevent_event_cb errorcb,
                       void *cbarg)
{
    bufferevent_setcb(be,
                      (flags & BEV_MOD_CB_READ ) ? readcb  : be->readcb ,
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

    /* sockets names */
    in4_t localname;
    in4_t peername;

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

    the->options = NULL;
    the->rdclosed = 0;
    the->wrclosed = 0;
    the->fd = -1;
    the->bevent = NULL;

    memset(&the->localname, 0, sizeof(in4_t));
    memset(&the->peername , 0, sizeof(in4_t));

    the->addst = NULL;
    the->adsrc = NULL;

    return the;
}

void stream_free(stream_t *the) {
    if (the->adsrc) free(the->adsrc);
    if (the->addst) free(the->addst);

    if (the->bevent != NULL)
        bufferevent_free(the->bevent);
    (void) close(the->fd);

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

    bufferevent_disable(stream->bevent, EV_WRITE);
    bufferevent_modcb(stream->bevent,
                      BEV_MOD_CB_READ | BEV_MOD_CB_WRITE,
                      NULL, NULL, NULL, stream);
    _check_for_stream_end(stream);
}

/* -------------------------------------------------------------------- */
void _onerror(bufferevent_t *be, short what, void *arg)  {
    stream_t *stream = (stream_t*) arg;

    if ((what & BEV_EVENT_ERROR)) {
        int rr = evutil_socket_geterror(bufferevent_getfd(be));

        if (rr != ECONNRESET) {
            stelog(stream, LOG_ERROR, "error client server: %s", strerror(rr));
            goto bailout;
        }
    }

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

    return ;

 bailout:
    stelog(stream, LOG_ERROR, "closing connection");
    stream_free(stream);
}

/* -------------------------------------------------------------------- */
void _onaccept(int fd, short ev, void *arg) {
    options_t *options = (options_t*) arg;
    stream_t  *stream;

    (void) ev;

    stream = stream_new();
    stream->options = options;

    {   socklen_t slen = sizeof(stream->peername);

        while ((stream->fd = accept(fd, (void*) &stream->peername, &slen)) < 0) {
            if (errno == EWOULDBLOCK)
                return ;
            if (errno == EINTR || errno == EAGAIN)
                continue ;
            goto bailout;
        }
    }

    stream->adsrc = inet4_ntop_x(&stream ->peername);
    stream->addst = inet4_ntop_x(&options->echoname);

    stelog(stream, LOG_INFO, "new client");

    fcntl(stream->fd, F_SETFL, fcntl(stream->fd, F_GETFL) | O_NONBLOCK);

    stream->bevent =
        bufferevent_socket_new(evb, stream->fd, BEV_OPT_DEFER_CALLBACKS);
    bufferevent_setcb(stream->bevent, _onread, NULL, _onerror, stream);
    bufferevent_enable(stream->bevent, EV_READ|EV_WRITE);

    return ;

 bailout:
    stream_free(stream);
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
int main(int argc, char *argv[]) {
    options_t options;
    event_t   onaccept;
    int       fd;

    _options(&options);
    _initialize_log4c(&options);

    if ((evb = event_init()) == NULL) {
        elog(LOG_FATAL, "cannot initialize libevent");
        return EXIT_FAILURE;
    }

    event_set_log_callback(_evlog);

    event_set_mem_functions(&xmalloc, &xrealloc, &free);

    if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        elog(LOG_FATAL, "socket(AF_INET, SOCK_STREAM) failed: %s", strerror(errno));
        return EXIT_FAILURE;
    }

    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);

    if (bind(fd, (void*) &options.echoname, sizeof(in4_t)) < 0) {
        elog(LOG_FATAL, "bind(port = %d): %s",
             ntohs(options.echoname.sin_port), strerror(errno));
        return EXIT_FAILURE;
    }

    if (listen(fd, 5) < 0) {
        elog(LOG_FATAL, "listen(): %s", strerror(errno));
        return EXIT_FAILURE;
    }

    event_set(&onaccept, fd, EV_READ|EV_PERSIST, _onaccept, &options);
    event_add(&onaccept, NULL);

    elog(LOG_NOTICE, "started");

    event_dispatch();

    return 0;
}
