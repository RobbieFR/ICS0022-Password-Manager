#include <stdio.h>
#include <string.h>
#include <strings.h>
#include "cli.h"

#define INPUT_SIZE 256

static const char ASCII_BANNER[] = 
    "               _______\n"
    "              |.-----.|\n"
    "              ||x . x||\n"
    "              ||_.-._||\n"
    "              `--)-(--`\n"
    "            __[=== o]___\n"
    "            |:::::::::::|\\\n"
    "            `-=========-`()\n"
    "      ICS0022 Secure password manager\n";

static const char LOGIN_MENU[] =
    "You may log in to access your data.\n"
    "LOGIN <username>    - Log into your account\n"
    "SIGNUP <username>   - Create a new account\n"
    "EXIT                - Exit and end the program\n";

static const char MAIN_MENU[] =
    "========== MAIN MENU ==========\n"
    "Available commands: \n"
    "ADD <url> <username>    - Add a new credential\n"
    "GET <url>               - Retrieve password for service\n"
    "DEL <url>               - Delete an entry\n"
    "LIST                    - List stored service URLs\n"
    "EXIT                    - Lock vault and exit\n";

void cli_print_banner(void) {
    printf("%s\n", ASCII_BANNER);
}

// Safely reads a line from stdin and removes the trailing newline
static int read_line(char *buf, int max_size) {
    if (fgets(buf, max_size, stdin) == NULL) {
        return 0;
    }

    size_t len = strlen(buf);
    if (len > 0 && buf[len - 1] == '\n') {
        buf[len - 1] = '\0';
    } else {
        int c;
        while ((c = getchar()) != '\n' && c != EOF);
    }
    return 1;
}

int cli_get_auth_command(char *username) {
    char line[INPUT_SIZE] = {0};
    char action[32] = {0};

    printf("%s> ", LOGIN_MENU);
    if (!read_line(line, sizeof(line))) {
        return 99; // Exit on EOF
    }

    // %63s ensures we don't overflow MAX_USERNAME_LEN
    int count = sscanf(line, "%31s %63s", action, username);
    if (count <= 0) {
        return -1;
    }

    if (strcasecmp(action, "EXIT") == 0) {
        return 99;
    }
    if (strcasecmp(action, "LOGIN") == 0) {
        if (count == 2) return 1;
        printf("[!] Usage: LOGIN <username>\n");
        return -1;
    }
    if (strcasecmp(action, "SIGNUP") == 0) {
        if (count == 2) return 2;
        printf("[!] Usage: SIGNUP <username>\n");
        return -1;
    }

    printf("[!] Unknown command.\n");
    return -1;
}

int cli_get_vault_command(char *url, char *username) {
    char line[INPUT_SIZE] = {0};
    char action[32] = {0};

    printf("\nvault> ");
    if (!read_line(line, sizeof(line))) {
        return 99;
    }

    // %127s bounds URL, %63s bounds username
    int count = sscanf(line, "%31s %127s %63s", action, url, username);
    if (count <= 0) {
        return -1;
    }

    if (strcasecmp(action, "EXIT") == 0) {
        return 99;
    }
    if (strcasecmp(action, "LIST") == 0) {
        return 4;
    }
    if (strcasecmp(action, "GET") == 0) {
        if (count >= 2) return 2;
        printf("[!] Usage: GET <url>\n");
        return -1;
    }
    if (strcasecmp(action, "DEL") == 0) {
        if (count >= 2) return 3;
        printf("[!] Usage: DEL <url>\n");
        return -1;
    }
    if (strcasecmp(action, "ADD") == 0) {
        if (count == 3) return 1;
        printf("[!] Usage: ADD <url> <username>\n");
        return -1;
    }

    printf("[!] Unknown command. Options:\n%s", MAIN_MENU);
    return -1;
}

void read_hidden_input(const char *prompt, char *buf, int max_len) {
    printf("%s", prompt);
    fflush(stdout);

    struct termios oldt, newt;
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~ECHO; // Disable echo

    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    
    if (fgets(buf, max_len, stdin) != NULL) {
        size_t len = strlen(buf);
        if (len > 0 && buf[len - 1] == '\n') {
            buf[len - 1] = '\0';
        }
    }

    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    printf("\n");
}