#include <stdio.h>
#include <stdlib.h>
#include <sodium.h>
#include <string.h>
#include <unistd.h>
#include "cli.h"
#include "crypto.h"
#include "db.h"

#define MAX_PASS_LEN 128

int main(void) {
    if (sodium_init() < 0) {
        fprintf(stderr, "[-] Failed to initialize libsodium.\n");
        return 1;
    }

    if (db_init("database.db") != 0) {
        return 1;
    }

    char username[MAX_USERNAME_LEN] = {0};
    char url[MAX_URL_LEN] = {0};
    char master_pass[MAX_PASS_LEN] = {0};

    int current_user_id = -1;
    unsigned char session_key[crypto_secretbox_KEYBYTES];

    cli_print_banner();

    // Auth loop: keep prompting until logged in or user types EXIT
    while (current_user_id < 0) {
        int auth = cli_get_auth_command(username);

        if (auth == 1) { // LOGIN
            read_hidden_input("Master password: ", master_pass, sizeof(master_pass));

            int uid = -1;
            char auth_hash[crypto_pwhash_STRBYTES];
            unsigned char kdf_salt[crypto_pwhash_SALTBYTES];

            if (db_get_user(username, &uid, auth_hash, kdf_salt) == 0 &&
                crypto_verify_pass(auth_hash, master_pass) == 0 &&
                crypto_derive_key(master_pass, kdf_salt, session_key) == 0) {
                current_user_id = uid;
                printf("[+] Vault unlocked for '%s'.\n", username);
            } else {
                printf("[-] Invalid username or master password.\n");
            }
            sodium_memzero(master_pass, sizeof(master_pass));

        } else if (auth == 2) { // SIGNUP
            read_hidden_input("New master password: ", master_pass, sizeof(master_pass));

            if (strlen(master_pass) < 8) {
                printf("[-] Master password must be at least 8 characters.\n");
                sodium_memzero(master_pass, sizeof(master_pass));
                continue;
            }

            char auth_hash[crypto_pwhash_STRBYTES];
            unsigned char kdf_salt[crypto_pwhash_SALTBYTES];
            randombytes_buf(kdf_salt, sizeof(kdf_salt));

            if (crypto_hash_pass(master_pass, auth_hash) == 0 &&
                db_create_user(username, auth_hash, kdf_salt) == 0) {
                printf("[+] Account '%s' created! You can now LOGIN %s.\n", username, username);
            } else {
                printf("[-] Could not create user (username may already exist).\n");
            }
            sodium_memzero(master_pass, sizeof(master_pass));

        } else if (auth == 99) { // EXIT
            printf("Exiting.\n");
            db_close();
            return 0;
        }
    }

    // Vault loop
    int running = 1;
    while (running) {
        int cmd = cli_get_vault_command(url, username);

        switch (cmd) {
            case 1: { // ADD
                char service_pass[MAX_PASS_LEN] = {0};
                read_hidden_input("Service password: ", service_pass, sizeof(service_pass));

                size_t pass_len = strlen(service_pass);
                if (pass_len == 0) {
                    printf("[-] Password cannot be empty.\n");
                    break;
                }

                unsigned char nonce[crypto_secretbox_NONCEBYTES];
                unsigned char ciphertext[DB_MAX_CIPHER];

                if (crypto_encrypt_vault_entry((const unsigned char *)service_pass, pass_len,
                                               session_key, nonce, ciphertext) == 0 &&
                    db_add_entry(current_user_id, url, username, nonce, ciphertext,
                                 pass_len + crypto_secretbox_MACBYTES) == 0) {
                    printf("[+] Added entry for %s (%s)\n", url, username);
                } else {
                    printf("[-] Failed to encrypt and store entry.\n");
                }
                sodium_memzero(service_pass, sizeof(service_pass));
                break;
            }
            case 2: { // GET
                char out_user[DB_MAX_TEXT] = {0};
                unsigned char nonce[crypto_secretbox_NONCEBYTES];
                unsigned char ciphertext[DB_MAX_CIPHER];
                size_t cipher_len = 0;

                if (db_get_entry(current_user_id, url, out_user, sizeof(out_user),
                                 nonce, ciphertext, &cipher_len) != 0) {
                    printf("[-] No entry found for %s\n", url);
                    break;
                }

                unsigned char decrypted[DB_MAX_TEXT] = {0};
                if (crypto_decrypt_vault_entry(ciphertext, cipher_len, nonce,
                                               session_key, decrypted) == 0) {
                    size_t plain_len = cipher_len - crypto_secretbox_MACBYTES;
                    decrypted[plain_len] = '\0';

                    printf("URL:      %s\n", url);
                    printf("Username: %s\n", out_user);
                    printf("Pass: %s\r", (char *)decrypted);
                    fflush(stdout);
                    sleep(3);
                    printf("Pass: [HIDDEN]                              \n");
                } else {
                    printf("[-] Decryption failed!\n");
                }
                sodium_memzero(decrypted, sizeof(decrypted));
                break;
            }
            case 3: { // DEL
                if (db_del_entry(current_user_id, url) == 0) {
                    printf("[+] Deleted entry for: %s\n", url);
                } else {
                    printf("[-] No entry found for: %s\n", url);
                }
                break;
            }
            case 4: { // LIST
                db_list_entries(current_user_id);
                break;
            }
            case 99: { // EXIT
                printf("Goodbye!\n");
                running = 0;
                break;
            }
            default:
                break;
        }
    }

    sodium_memzero(session_key, sizeof(session_key));
    db_close();
    return 0;
}