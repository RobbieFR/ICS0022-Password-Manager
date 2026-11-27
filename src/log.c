#include "log.h"
#include "validation.h"
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static FILE *log_fp = NULL;

int log_init(const char *log_path) {
    if (!log_path || log_path[0] == '\0') {
        return -1;
    }

    if (log_fp) {
        fclose(log_fp);
        log_fp = NULL;
    }

    int fd = open(log_path, O_WRONLY | O_CREAT | O_APPEND, 0600);
    if (fd < 0) {
        return -1;
    }

    /* Enforce owner-only permissions even if the file already existed */
    if (fchmod(fd, 0600) != 0) {
        close(fd);
        return -1;
    }

    log_fp = fdopen(fd, "a");
    if (!log_fp) {
        close(fd);
        return -1;
    }

    return 0;
}

void log_close(void) {
    if (log_fp) {
        fflush(log_fp);
        fclose(log_fp);
        log_fp = NULL;
    }
}

void log_event(const char *event, const char *user, int user_id,
               const char *outcome, const char *detail) {
    if (!log_fp) {
        return;
    }

    time_t now = time(NULL);
    struct tm utc_tm;
    char timestamp[32] = "1970-01-01T00:00:00Z";
    if (gmtime_r(&now, &utc_tm) != NULL) {
        strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%SZ", &utc_tm);
    }

    char safe_event[64];
    char safe_user[MAX_USERNAME_LEN];
    char safe_outcome[32];
    char safe_detail[160];

    sanitize_for_log(event ? event : "UNKNOWN", safe_event, sizeof(safe_event));
    sanitize_for_log(user ? user : "-", safe_user, sizeof(safe_user));
    sanitize_for_log(outcome ? outcome : "UNKNOWN", safe_outcome, sizeof(safe_outcome));
    sanitize_for_log(detail ? detail : "", safe_detail, sizeof(safe_detail));

    fprintf(log_fp,
            "{\"timestamp\":\"%s\",\"event\":\"%s\",\"user\":\"%s\","
            "\"user_id\":%d,\"outcome\":\"%s\",\"detail\":\"%s\"}\n",
            timestamp, safe_event, safe_user, user_id, safe_outcome, safe_detail);
    fflush(log_fp);
}
