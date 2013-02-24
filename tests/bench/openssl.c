#include <sys/types.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

#include <fcntl.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

/* -------------------------------------------------------------------- */
typedef struct sockaddr sockaddr_t;
typedef struct sockaddr_in in4_t;

/* -------------------------------------------------------------------- */
static void error(const char *message)
    __attribute__((noreturn));

static void error(const char *message) {
    (void) fprintf(stderr, "%s: %s", message, strerror(errno));
    exit(EXIT_FAILURE);
}

/* -------------------------------------------------------------------- */
static uint8_t udata[1024 * 1024];

static udata_initialize(void) {
    int    fd = -1;
    size_t position = 0;

    if ((fd = open("/dev/urandom", O_RDONLY)) < 0)
        error("open(/dev/urandom");
    while (position < sizeof(udata)) {
        ssize_t rr = read(fd, &udata[position], sizeof(udata) - position);

        if (rr <= 0)
            error("reading from /dev/urandom");
        position += rr;
    }
}

/* -------------------------------------------------------------------- */
static const int zero = 0;
static const int one  = 1;

void server(void) {
    int   servfd = -1;
    in4_t sockname;
    in4_t peername;

    if ((servfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        error("socket(AF_INET, SOCK_STREAM)");

    memset(&sockname, 0, sizeof(in4_t));
    sockname.sin_family = AF_INET;
    sockname.sin_addr   = (struct in_addr) { .s_addr = INADDR_ANY };
    sockname.sin_port   = htons(5000);

    setsockopt(servfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    if (bind(servfd, (sockaddr_t*) &sockname, sizeof(in4_t)) < 0)
        error("cannot bind socket");
    if (listen(servfd, 5) < 0)
        error("cannot set socket in listening mode");

    memset(&peername, 0, sizeof(in4_t));
}

/* -------------------------------------------------------------------- */
void client(void) {
}

/* -------------------------------------------------------------------- */
int main(void) {
    pid_t pid;

    (void) SSL_library_init();
    udata_initialize();

    if ((pid = fork()) < 0)
        error("fork(2)");

    if (pid == 0) { server(); } else { client(); }

    return EXIT_SUCCESS;
}
