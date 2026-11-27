#ifndef VALIDATION_H
#define VALIDATION_H

#include <stddef.h>

#define MIN_USERNAME_LEN     3
#define MAX_USERNAME_LEN     64
#define MIN_URL_LEN          1
#define MAX_URL_LEN          128
#define MIN_MASTER_PASS_LEN  12
#define MIN_SERVICE_PASS_LEN 1
#define MAX_PASS_LEN         128

/*
 * Validates a username: length in [MIN_USERNAME_LEN, MAX_USERNAME_LEN - 1],
 * ASCII alphanumeric plus '_', '-', '.', '@'.
 * Returns 0 if valid, -1 otherwise.
 */
int validate_username(const char *username);

/*
 * Validates a service URL/identifier: length in [MIN_URL_LEN, MAX_URL_LEN - 1],
 * printable non-whitespace ASCII excluding quotes, backticks, backslashes, and semicolons.
 * Returns 0 if valid, -1 otherwise.
 */
int validate_url(const char *url);

/*
 * Validates a master password: length in [MIN_MASTER_PASS_LEN, MAX_PASS_LEN - 1],
 * printable ASCII only, containing at least one uppercase letter, one lowercase letter,
 * one digit, and one special character.
 * Returns 0 if valid, -1 otherwise.
 */
int validate_master_password(const char *password);

/*
 * Validates a stored service password: length in [MIN_SERVICE_PASS_LEN, MAX_PASS_LEN - 1],
 * printable ASCII characters only.
 * Returns 0 if valid, -1 otherwise.
 */
int validate_service_password(const char *password);

/*
 * Sanitizes an untrusted string for safe inclusion in a JSON log field.
 * Replaces control characters, quotes, and backslashes with '_'.
 */
void sanitize_for_log(const char *input, char *out, size_t out_size);

#endif /* VALIDATION_H */
