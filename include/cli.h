#include <termios.h>
#include <unistd.h>

#ifndef CLI_H
#define CLI_H

#define MAX_USERNAME_LEN 64
#define MAX_URL_LEN      128

void cli_print_banner(void);

// Returns: 1 for LOGIN, 2 for SIGNUP, 99 for EXIT, -1 for invalid
int cli_get_auth_command(char *username);

// Returns: 1 for ADD, 2 for GET, 3 for DEL, 4 for LIST, 99 for EXIT, -1 for invalid
int cli_get_vault_command(char *url, char *username);

void read_hidden_input(const char *prompt, char *buf, int max_len);

#endif // CLI_H