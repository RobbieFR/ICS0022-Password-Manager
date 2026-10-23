#include <stdio.h>
#include <stdlib.h>
#include <sodium.h>
#include <string.h>
#include "cli.h"
#include "crypto.h"
#include "db.h"


int main(void) {

    //////////// TEST DB ////////////
    printf("=== Starting DB Layer Test ===\n");

    // 1. Initialize test database
    if (db_init("test_vault.db") != 0) {
        printf("[-] db_init failed!\n");
        return 0;
    }
    printf("[+] Database initialized.\n");

    // 2. Create a dummy user
    const char *test_user = "robbie";
    char dummy_hash[crypto_pwhash_STRBYTES] = "$argon2id$v=19$m=65536,t=2,p=1$dummysalt$dummyhash";
    unsigned char dummy_salt[crypto_pwhash_SALTBYTES];
    randombytes_buf(dummy_salt, sizeof(dummy_salt));

    if (db_create_user(test_user, dummy_hash, dummy_salt) == 0) {
        printf("[+] User '%s' created.\n", test_user);
    } else {
        printf("[!] User '%s' already exists (or creation failed).\n", test_user);
    }

    // 3. Retrieve the user
    int user_id = -1;
    char fetched_hash[crypto_pwhash_STRBYTES];
    unsigned char fetched_salt[crypto_pwhash_SALTBYTES];

    if (db_get_user(test_user, &user_id, fetched_hash, fetched_salt) == 0) {
        printf("[+] Fetched user '%s' -> ID: %d, Hash: %.25s...\n",
               test_user, user_id, fetched_hash);
    } else {
        printf("[-] db_get_user failed!\n");
        db_close();
        return 0;
    }

    // 4. Add two concrete vault entries
    unsigned char nonce1[crypto_secretbox_NONCEBYTES];
    randombytes_buf(nonce1, sizeof(nonce1));
    const unsigned char cipher1[] = {0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02};

    if (db_add_entry(user_id, "github.com", "RobbieFR", nonce1, cipher1, sizeof(cipher1)) == 0) {
        printf("[+] Added entry for github.com\n");
    }

    unsigned char nonce2[crypto_secretbox_NONCEBYTES];
    randombytes_buf(nonce2, sizeof(nonce2));
    const unsigned char cipher2[] = {0xCA, 0xFE, 0xBA, 0xBE, 0x99, 0x88};

    if (db_add_entry(user_id, "taltech.ee", "robbie@taltech.ee", nonce2, cipher2, sizeof(cipher2)) == 0) {
        printf("[+] Added entry for taltech.ee\n");
    }

    // 5. List all entries for this user
    printf("[*] Listing entries for user_id %d:\n", user_id);
    db_list_entries(user_id);

    // 6. Retrieve a specific entry and verify bytes
    char out_username[DB_MAX_TEXT];
    unsigned char out_nonce[crypto_secretbox_NONCEBYTES];
    unsigned char out_cipher[DB_MAX_CIPHER];
    size_t out_cipher_len = 0;

    if (db_get_entry(user_id, "github.com", out_username, sizeof(out_username),
                     out_nonce, out_cipher, &out_cipher_len) == 0) {
        printf("[+] Retrieved 'github.com' -> Username: %s, Cipher len: %zu bytes\n",
               out_username, out_cipher_len);

        if (out_cipher_len == sizeof(cipher1) &&
            memcmp(out_cipher, cipher1, sizeof(cipher1)) == 0 &&
            memcmp(out_nonce, nonce1, sizeof(nonce1)) == 0) {
            printf("[+] Blob verification PASSED (nonce and ciphertext match!).\n");
        } else {
            printf("[-] Blob verification FAILED!\n");
        }
    } else {
        printf("[-] Failed to retrieve 'github.com'\n");
    }

    // 7. Delete an entry and list again
    if (db_del_entry(user_id, "taltech.ee") == 0) {
        printf("[+] Deleted entry 'taltech.ee'\n");
    }
    db_list_entries(user_id);

    db_close();
    printf("=== DB Layer Test Complete ===\n\n");

    return 0;

    ///// Thanks gemini for the test
    /////////////////////////////////

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