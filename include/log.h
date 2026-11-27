#ifndef LOG_H
#define LOG_H

/*
 * Initializes structured JSON Lines logging to log_path with 0600 permissions.
 * Returns 0 on success, -1 on failure.
 */
int log_init(const char *log_path);

/* Closes the log file cleanly. */
void log_close(void);

/*
 * Writes a structured JSON Lines security event.
 * Never pass passwords, keys, salts, nonces, or ciphertexts to this function.
 */
void log_event(const char *event, const char *user, int user_id,
               const char *outcome, const char *detail);

#endif /* LOG_H */
