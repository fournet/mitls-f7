/* -------------------------------------------------------------------- */
#include <sys/types.h>
#include <stdlib.h>
#include <stdio.h>

#include <log4c.h>
#include <event.h>

#include "echo-log.h"

/* -------------------------------------------------------------------- */
log4c_category_t *logcat = NULL;

/* -------------------------------------------------------------------- */
void initialize_log4c(void) {
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

    setvbuf(stderr, NULL, _IONBF, 0);
}

/* -------------------------------------------------------------------- */
void elog(int level, const char *format, ...) {
    va_list ap;

    if (level > log4c_category_get_priority(logcat))
        return ;

    va_start(ap, format);
    log4c_category_vlog(logcat, level, format, ap);
    va_end(ap);
}

/* -------------------------------------------------------------------- */
void _evlog(int severity, const char *msg) { /* event logger CB */
         if (severity == _EVENT_LOG_DEBUG) severity = LOG_DEBUG;
    else if (severity == _EVENT_LOG_MSG)   severity = LOG_NOTICE;
    else if (severity == _EVENT_LOG_WARN)  severity = LOG_WARN;
    else if (severity == _EVENT_LOG_ERR)   severity = LOG_ERROR;
    else severity = LOG4C_PRIORITY_UNKNOWN;

    log4c_category_log(logcat, severity, "%s", (char*) msg);
}
