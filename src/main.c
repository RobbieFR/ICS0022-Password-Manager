#include <stdio.h>
#include <stdlib.h>
#include "cli.h"

int main(void) {
    

    //////////////// TEMP TEST (HIDDEN PASS) /////////////////////
    char test_pass[128];
    read_hidden_input("Enter a password : ", test_pass, sizeof(test_pass));
    printf("Pass: %s (Will disapear in 3sec) \r", test_pass);
    fflush(stdout);
    sleep(3);
    printf("Pass: [HIDDEN]          \n");
    /////////////////////////////////////////////////////////////



    char username[MAX_USERNAME_LEN] = {0};
    char url[MAX_URL_LEN] = {0};

    cli_print_banner();

    int auth = cli_get_auth_command(username);
    if (auth == 1) {
        printf("Logging in: %s\n", username);
    } else if (auth == 2) {
        printf("Signing up: %s\n", username);
    } else {
        printf("Exiting.\n");
        return 0;
    }

    // Vault loop
    int running = 1;
    while (running) {
        int cmd = cli_get_vault_command(url, username);

        switch (cmd) {
            case 1: // ADD
                printf("Adding entry -> URL: %s, User: %s\n", url, username);
                break;
            case 2: // GET
                printf("Getting password for: %s\n", url);
                break;
            case 3: // DEL
                printf("Deleting entry for: %s\n", url);
                break;
            case 4: // LIST
                printf("Listing all entries...\n");
                break;
            case 99: // EXIT
                printf("Goodbye!\n");
                running = 0;
                break;
            default:
                break;
        }
    }

    return 0;
}