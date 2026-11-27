#ifndef CLI_H
#define CLI_H

#include <stddef.h>
#include "validation.h"

/* Authentication menu command codes */
typedef enum {
    AUTH_CMD_INVALID = -1,
    AUTH_CMD_LOGIN   = 1,
    AUTH_CMD_SIGNUP  = 2,
    AUTH_CMD_EXIT    = 99
} AuthCommand;

/* Vault menu command codes */
typedef enum {
    VAULT_CMD_INVALID = -1,
    VAULT_CMD_ADD     = 1,
    VAULT_CMD_GET     = 2,
    VAULT_CMD_UPDATE  = 3,
    VAULT_CMD_DEL     = 4,
    VAULT_CMD_LIST    = 5,
    VAULT_CMD_HELP    = 6,
    VAULT_CMD_EXIT    = 99
} VaultCommand;

void cli_print_banner(void);
void cli_print_vault_menu(void);

AuthCommand cli_get_auth_command(char *username, size_t username_size);
VaultCommand cli_get_vault_command(char *url, size_t url_size,
                                   char *username, size_t username_size);

/*
 * Reads a hidden input line without echoing to the terminal.
 * Returns 0 on success, -1 on EOF, error, or input exceeding max_len - 1.
 */
int read_hidden_input(const char *prompt, char *buf, size_t max_len);

/* Async-signal-safe helper to restore terminal echo on SIGINT/SIGTERM. */
void cli_restore_terminal(void);

/*
 * Copies a secret to the system clipboard without invoking a shell or
 * printing plaintext to stdout, and schedules automatic clearing after
 * clear_seconds. Returns 0 on success, -1 if no clipboard tool is available.
 */
int cli_copy_to_clipboard(const char *secret, unsigned int clear_seconds);

#endif /* CLI_H */
