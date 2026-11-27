#include "cli.h"
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>
#include <sodium.h>

#define INPUT_SIZE 256

static struct termios saved_termios;
static volatile sig_atomic_t termios_modified = 0;

static const char ASCII_BANNER[] =
    "               _______\n"
    "              |.-----.|\n"
    "              ||x . x||\n"
    "              ||_.-._||\n"
    "              `--)-(--`\n"
    "            __[=== o]___\n"
    "            |:::::::::::|\\\n"
    "            `-=========-`()\n"
    "      ICS0022 Secure Password Manager\n";

static const char LOGIN_MENU[] =
    "\nYou may log in to access your vault.\n"
    "LOGIN <username>              - Log into your account\n"
    "SIGNUP <username>             - Create a new account\n"
    "EXIT                          - Exit the program\n";

static const char MAIN_MENU[] =
    "\n========== MAIN MENU ==========\n"
    "Available commands:\n"
    "ADD <url> <username>          - Add a new credential\n"
    "GET <url>                     - Copy password to clipboard\n"
    "UPDATE <url> <new_username>   - Update an existing credential\n"
    "DEL <url>                     - Delete an entry\n"
    "LIST                          - List stored service URLs\n"
    "HELP                          - Show this menu\n"
    "EXIT                          - Lock vault and exit\n";

void cli_print_banner(void) {
    printf("%s\n", ASCII_BANNER);
}

void cli_print_vault_menu(void) {
    printf("%s", MAIN_MENU);
}

void cli_restore_terminal(void) {
    if (termios_modified) {
        tcsetattr(STDIN_FILENO, TCSANOW, &saved_termios);
        termios_modified = 0;
    }
}

/*
 * Reads a line safely from stdin.
 * Returns:
 *   1  on success
 *   0  on EOF or interrupted read
 *  -1  if input exceeded max_size - 1 characters (excess drained)
 */
static int read_line(char *buf, size_t max_size) {
    if (!buf || max_size == 0) {
        return 0;
    }

    if (fgets(buf, (int)max_size, stdin) == NULL) {
        buf[0] = '\0';
        return 0;
    }

    size_t len = strlen(buf);
    if (len > 0 && buf[len - 1] == '\n') {
        buf[len - 1] = '\0';
        return 1;
    }

    /* Check whether EOF was reached without a trailing newline */
    if (feof(stdin)) {
        return 1;
    }

    /* Input overflowed buffer: drain remaining characters on this line */
    int c;
    while ((c = getchar()) != '\n' && c != EOF) {
        /* discard */
    }
    buf[0] = '\0';
    return -1;
}

AuthCommand cli_get_auth_command(char *username, size_t username_size) {
    if (!username || username_size < MAX_USERNAME_LEN) {
        return AUTH_CMD_INVALID;
    }

    char line[INPUT_SIZE] = {0};
    char action[32] = {0};
    char extra[2] = {0};
    username[0] = '\0';

    printf("%s> ", LOGIN_MENU);
    fflush(stdout);

    int status = read_line(line, sizeof(line));
    if (status == 0) {
        return AUTH_CMD_EXIT;
    }
    if (status < 0) {
        printf("[!] Input too long.\n");
        return AUTH_CMD_INVALID;
    }

    int count = sscanf(line, "%31s %63s %1s", action, username, extra);
    if (count <= 0) {
        return AUTH_CMD_INVALID;
    }

    if (strcasecmp(action, "EXIT") == 0) {
        if (count == 1) {
            return AUTH_CMD_EXIT;
        }
        printf("[!] Usage: EXIT\n");
        return AUTH_CMD_INVALID;
    }

    if (strcasecmp(action, "LOGIN") == 0) {
        if (count != 2) {
            printf("[!] Usage: LOGIN <username>\n");
            return AUTH_CMD_INVALID;
        }
        if (validate_username(username) != 0) {
            printf("[!] Invalid username (3-63 chars; letters, digits, '_', '-', '.', '@').\n");
            return AUTH_CMD_INVALID;
        }
        return AUTH_CMD_LOGIN;
    }

    if (strcasecmp(action, "SIGNUP") == 0) {
        if (count != 2) {
            printf("[!] Usage: SIGNUP <username>\n");
            return AUTH_CMD_INVALID;
        }
        if (validate_username(username) != 0) {
            printf("[!] Invalid username (3-63 chars; letters, digits, '_', '-', '.', '@').\n");
            return AUTH_CMD_INVALID;
        }
        return AUTH_CMD_SIGNUP;
    }

    printf("[!] Unknown command.\n");
    return AUTH_CMD_INVALID;
}

VaultCommand cli_get_vault_command(char *url, size_t url_size,
                                   char *username, size_t username_size) {
    if (!url || url_size < MAX_URL_LEN || !username || username_size < MAX_USERNAME_LEN) {
        return VAULT_CMD_INVALID;
    }

    char line[INPUT_SIZE] = {0};
    char action[32] = {0};
    char extra[2] = {0};
    url[0] = '\0';
    username[0] = '\0';

    printf("\nvault> ");
    fflush(stdout);

    int status = read_line(line, sizeof(line));
    if (status == 0) {
        return VAULT_CMD_EXIT;
    }
    if (status < 0) {
        printf("[!] Input too long.\n");
        return VAULT_CMD_INVALID;
    }

    int count = sscanf(line, "%31s %127s %63s %1s", action, url, username, extra);
    if (count <= 0) {
        return VAULT_CMD_INVALID;
    }

    if (strcasecmp(action, "EXIT") == 0) {
        if (count == 1) return VAULT_CMD_EXIT;
        printf("[!] Usage: EXIT\n");
        return VAULT_CMD_INVALID;
    }

    if (strcasecmp(action, "HELP") == 0) {
        if (count == 1) return VAULT_CMD_HELP;
        printf("[!] Usage: HELP\n");
        return VAULT_CMD_INVALID;
    }

    if (strcasecmp(action, "LIST") == 0) {
        if (count == 1) return VAULT_CMD_LIST;
        printf("[!] Usage: LIST\n");
        return VAULT_CMD_INVALID;
    }

    if (strcasecmp(action, "GET") == 0) {
        if (count != 2) {
            printf("[!] Usage: GET <url>\n");
            return VAULT_CMD_INVALID;
        }
        if (validate_url(url) != 0) {
            printf("[!] Invalid URL format.\n");
            return VAULT_CMD_INVALID;
        }
        return VAULT_CMD_GET;
    }

    if (strcasecmp(action, "DEL") == 0) {
        if (count != 2) {
            printf("[!] Usage: DEL <url>\n");
            return VAULT_CMD_INVALID;
        }
        if (validate_url(url) != 0) {
            printf("[!] Invalid URL format.\n");
            return VAULT_CMD_INVALID;
        }
        return VAULT_CMD_DEL;
    }

    if (strcasecmp(action, "ADD") == 0) {
        if (count != 3) {
            printf("[!] Usage: ADD <url> <username>\n");
            return VAULT_CMD_INVALID;
        }
        if (validate_url(url) != 0) {
            printf("[!] Invalid URL format.\n");
            return VAULT_CMD_INVALID;
        }
        if (validate_username(username) != 0) {
            printf("[!] Invalid service username (3-63 chars; letters, digits, '_', '-', '.', '@').\n");
            return VAULT_CMD_INVALID;
        }
        return VAULT_CMD_ADD;
    }

    if (strcasecmp(action, "UPDATE") == 0) {
        if (count != 3) {
            printf("[!] Usage: UPDATE <url> <new_username>\n");
            return VAULT_CMD_INVALID;
        }
        if (validate_url(url) != 0) {
            printf("[!] Invalid URL format.\n");
            return VAULT_CMD_INVALID;
        }
        if (validate_username(username) != 0) {
            printf("[!] Invalid service username (3-63 chars; letters, digits, '_', '-', '.', '@').\n");
            return VAULT_CMD_INVALID;
        }
        return VAULT_CMD_UPDATE;
    }

    printf("[!] Unknown command. Type HELP to see available commands.\n");
    return VAULT_CMD_INVALID;
}

int read_hidden_input(const char *prompt, char *buf, size_t max_len) {
    if (!buf || max_len < 2) {
        return -1;
    }

    if (prompt) {
        printf("%s", prompt);
        fflush(stdout);
    }

    int is_tty = isatty(STDIN_FILENO);
    if (is_tty) {
        if (tcgetattr(STDIN_FILENO, &saved_termios) != 0) {
            return -1;
        }
        struct termios newt = saved_termios;
        newt.c_lflag &= (tcflag_t)(~ECHO);
        if (tcsetattr(STDIN_FILENO, TCSANOW, &newt) != 0) {
            return -1;
        }
        termios_modified = 1;
    }

    int result = 0;
    if (fgets(buf, (int)max_len, stdin) == NULL) {
        sodium_memzero(buf, max_len);
        result = -1;
    } else {
        size_t len = strlen(buf);
        if (len > 0 && buf[len - 1] == '\n') {
            buf[len - 1] = '\0';
        } else if (!feof(stdin)) {
            /* Drain excess input so password tail cannot leak into the next prompt */
            int c;
            while ((c = getchar()) != '\n' && c != EOF) {
                /* discard */
            }
            sodium_memzero(buf, max_len);
            result = -1;
        }
    }

    if (is_tty) {
        cli_restore_terminal();
        printf("\n");
    }

    return result;
}

/* Checks whether an executable exists in PATH */
static int command_exists_in_path(const char *cmd) {
    const char *path_env = getenv("PATH");
    if (!path_env || !cmd) {
        return 0;
    }

    char path_copy[1024];
    strncpy(path_copy, path_env, sizeof(path_copy) - 1);
    path_copy[sizeof(path_copy) - 1] = '\0';

    char *saveptr = NULL;
    for (char *dir = strtok_r(path_copy, ":", &saveptr);
         dir != NULL;
         dir = strtok_r(NULL, ":", &saveptr)) {
        char candidate[1024];
        int n = snprintf(candidate, sizeof(candidate), "%s/%s", dir, cmd);
        if (n > 0 && (size_t)n < sizeof(candidate) && access(candidate, X_OK) == 0) {
            return 1;
        }
    }
    return 0;
}

/* Runs a clipboard command via fork/execvp (no shell) and feeds data on stdin */
static int run_clipboard_tool(char *const argv[], const char *data, size_t data_len) {
    int pipefd[2];
    if (pipe(pipefd) != 0) {
        return -1;
    }

    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }

    if (pid == 0) {
        /* Child process */
        close(pipefd[1]);
        if (dup2(pipefd[0], STDIN_FILENO) < 0) {
            _exit(127);
        }
        close(pipefd[0]);

        /* Silence tool stdout/stderr */
        FILE *devnull = fopen("/dev/null", "w");
        if (devnull) {
            dup2(fileno(devnull), STDOUT_FILENO);
            dup2(fileno(devnull), STDERR_FILENO);
            fclose(devnull);
        }

        execvp(argv[0], argv);
        _exit(127);
    }

    /* Parent process */
    close(pipefd[0]);

    size_t written = 0;
    while (written < data_len) {
        ssize_t n = write(pipefd[1], data + written, data_len - written);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        written += (size_t)n;
    }
    close(pipefd[1]);

    int status = 0;
    if (waitpid(pid, &status, 0) < 0) {
        return -1;
    }
    if (written != data_len) {
        return -1;
    }
    return (WIFEXITED(status) && WEXITSTATUS(status) == 0) ? 0 : -1;
}

/* Spawns a detached background process to clear the clipboard after delay */
static void schedule_clipboard_clear(char *const argv[], unsigned int clear_seconds) {
    if (clear_seconds == 0) {
        return;
    }

    pid_t pid = fork();
    if (pid < 0) {
        return;
    }
    if (pid == 0) {
        /* Double-fork so the parent never accumulates zombie processes */
        pid_t grandchild = fork();
        if (grandchild == 0) {
            sleep(clear_seconds);
            (void)run_clipboard_tool(argv, "", 0);
            _exit(0);
        }
        _exit(0);
    }

    (void)waitpid(pid, NULL, 0);
}

int cli_copy_to_clipboard(const char *secret, unsigned int clear_seconds) {
    if (!secret) {
        return -1;
    }

    char *wl_argv[]   = { "wl-copy", NULL };
    char *xclip_argv[] = { "xclip", "-selection", "clipboard", NULL };
    char *xsel_argv[]  = { "xsel", "--clipboard", "--input", NULL };
    char *pb_argv[]    = { "pbcopy", NULL };

    char **selected = NULL;
    if (getenv("WAYLAND_DISPLAY") && command_exists_in_path("wl-copy")) {
        selected = wl_argv;
    } else if (getenv("DISPLAY") && command_exists_in_path("xclip")) {
        selected = xclip_argv;
    } else if (getenv("DISPLAY") && command_exists_in_path("xsel")) {
        selected = xsel_argv;
    } else if (command_exists_in_path("pbcopy")) {
        selected = pb_argv;
    } else if (command_exists_in_path("wl-copy")) {
        selected = wl_argv;
    } else if (command_exists_in_path("xclip")) {
        selected = xclip_argv;
    } else if (command_exists_in_path("xsel")) {
        selected = xsel_argv;
    }

    if (!selected) {
        return -1;
    }

    if (run_clipboard_tool(selected, secret, strlen(secret)) != 0) {
        return -1;
    }

    schedule_clipboard_clear(selected, clear_seconds);
    return 0;
}
