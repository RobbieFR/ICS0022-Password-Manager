#include "validation.h"
#include <ctype.h>
#include <string.h>

int validate_username(const char *username) {
    if (!username) {
        return -1;
    }

    size_t len = strlen(username);
    if (len < MIN_USERNAME_LEN || len >= MAX_USERNAME_LEN) {
        return -1;
    }

    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)username[i];
        if (!(isalnum(c) || c == '_' || c == '-' || c == '.' || c == '@')) {
            return -1;
        }
    }
    return 0;
}

int validate_url(const char *url) {
    if (!url) {
        return -1;
    }

    size_t len = strlen(url);
    if (len < MIN_URL_LEN || len >= MAX_URL_LEN) {
        return -1;
    }

    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)url[i];
        /* Require printable non-whitespace ASCII */
        if (c < 0x21 || c > 0x7E) {
            return -1;
        }
        /* Reject characters commonly used in injection or quoting attacks */
        if (c == '\'' || c == '"' || c == '`' || c == '\\' || c == ';') {
            return -1;
        }
    }
    return 0;
}

int validate_master_password(const char *password) {
    if (!password) {
        return -1;
    }

    size_t len = strlen(password);
    if (len < MIN_MASTER_PASS_LEN || len >= MAX_PASS_LEN) {
        return -1;
    }

    int has_upper = 0;
    int has_lower = 0;
    int has_digit = 0;
    int has_special = 0;

    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)password[i];
        /* Require printable ASCII (0x20..0x7E) */
        if (c < 0x20 || c > 0x7E) {
            return -1;
        }
        if (isupper(c)) {
            has_upper = 1;
        } else if (islower(c)) {
            has_lower = 1;
        } else if (isdigit(c)) {
            has_digit = 1;
        } else {
            has_special = 1;
        }
    }

    if (!(has_upper && has_lower && has_digit && has_special)) {
        return -1;
    }
    return 0;
}

int validate_service_password(const char *password) {
    if (!password) {
        return -1;
    }

    size_t len = strlen(password);
    if (len < MIN_SERVICE_PASS_LEN || len >= MAX_PASS_LEN) {
        return -1;
    }

    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)password[i];
        if (c < 0x20 || c > 0x7E) {
            return -1;
        }
    }
    return 0;
}

void sanitize_for_log(const char *input, char *out, size_t out_size) {
    if (!out || out_size == 0) {
        return;
    }
    if (!input) {
        out[0] = '\0';
        return;
    }

    size_t i = 0;
    for (; input[i] != '\0' && i < out_size - 1; i++) {
        unsigned char c = (unsigned char)input[i];
        if (c < 0x20 || c > 0x7E || c == '"' || c == '\\') {
            out[i] = '_';
        } else {
            out[i] = (char)c;
        }
    }
    out[i] = '\0';
}
