#include <stdio.h>
#include <stdlib.h>
#include <sodium.h>
#include <string.h>
#include "cli.h"
#include "crypto.h"

int main(void) {
    

//////////////// TEMP TEST (CRYPTO) /////////////////////
    printf("--- CRYPTO TEST ---\n");

    // 1. Hash test (Auth)
    const char *master_password = "I_love_the_secure_programming_class";
    printf("Master Password: %s\n", master_password);
    
    char hash[crypto_pwhash_STRBYTES];
    if (crypto_hash_pass(master_password, hash) == 0) {
        printf("Argon2id hash: %s\n", hash);
    }

    if (crypto_verify_pass(hash, master_password) == 0) {
        printf("Password check: SUCCESS\n");
    }

    // 2. Key derivation test
    unsigned char salt[crypto_pwhash_SALTBYTES];
    randombytes_buf(salt, sizeof(salt)); // Generate a random salt
    
    printf("Salt (hex): ");
    for (size_t i = 0; i < sizeof(salt); i++) printf("%02x", salt[i]);
    printf("\n");
    
    unsigned char key[crypto_secretbox_KEYBYTES];
    if (crypto_derive_key(master_password, salt, key) == 0) {
        printf("Derived Key (hex): ");
        for (size_t i = 0; i < sizeof(key); i++) printf("%02x", key[i]);
        printf("\n");
    }

    // 3. Encryption test (Vault)
    const char *secret_password = "Password123";
    printf("\nSecret to encrypt: %s\n", secret_password);
    size_t message_len = strlen(secret_password) + 1; // +1 to include the final '\0'
    
    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    size_t ciphertext_len = message_len + crypto_secretbox_MACBYTES;
    unsigned char ciphertext[ciphertext_len];
    
    if (crypto_encrypt_vault_entry((const unsigned char *)secret_password, message_len, key, nonce, ciphertext) == 0) {
        printf("Nonce (hex): ");
        for (size_t i = 0; i < sizeof(nonce); i++) printf("%02x", nonce[i]);
        printf("\n");

        printf("Ciphertext (hex): ");
        for (size_t i = 0; i < ciphertext_len; i++) printf("%02x", ciphertext[i]);
        printf("\n");
    }

    // 4. Decryption test
    unsigned char decrypted[message_len];
    if (crypto_decrypt_vault_entry(ciphertext, ciphertext_len, nonce, key, decrypted) == 0) {
        printf("Decrypted data: %s\n", decrypted);
    } else {
        printf("Decryption failed\n");
    }
    printf("-----------------------\n");
    return 0;
    // Thanks Gemini for the tests !
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