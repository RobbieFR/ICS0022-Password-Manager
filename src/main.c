#include <signal.h>
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>

#include "cli.h"
#include "crypto.h"
#include "db.h"
#include "log.h"
#include "validation.h"

#define CLIPBOARD_CLEAR_SECONDS 15
#define MAX_FAILED_LOGINS       5
#define LOCKOUT_SECONDS         15

static volatile sig_atomic_t g_stop_requested = 0;

static void handle_signal(int sig) {
    (void)sig;
    g_stop_requested = 1;
    cli_restore_terminal();
}

static void install_signal_handlers(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_signal;
    sigemptyset(&sa.sa_mask);
    /* Do not set SA_RESTART so blocking stdin reads exit promptly on Ctrl+C */
    sa.sa_flags = 0;

    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
}

static void disable_core_dumps(void) {
    struct rlimit rl;
    rl.rlim_cur = 0;
    rl.rlim_max = 0;
    (void)setrlimit(RLIMIT_CORE, &rl);
}

int main(void) {
    disable_core_dumps();
    install_signal_handlers();

    if (sodium_init() < 0) {
        fprintf(stderr, "[-] Failed to initialize cryptographic subsystem.\n");
        return 1;
    }

    if (crypto_init() != 0) {
        fprintf(stderr, "[-] Failed to initialize cryptographic parameters.\n");
        return 1;
    }

    if (log_init("vault.log") != 0) {
        fprintf(stderr, "[-] Warning: Could not open audit log file.\n");
    }

    if (db_init("database.db") != 0) {
        log_event("STARTUP", "-", -1, "FAILURE", "database initialization failed");
        log_close();
        return 1;
    }

    log_event("STARTUP", "-", -1, "SUCCESS", "application started");

    char current_username[MAX_USERNAME_LEN] = {0};
    char entry_username[MAX_USERNAME_LEN] = {0};
    char url[MAX_URL_LEN] = {0};
    char master_pass[MAX_PASS_LEN] = {0};
    char confirm_pass[MAX_PASS_LEN] = {0};

    int current_user_id = -1;
    unsigned char session_key[crypto_secretbox_KEYBYTES] = {0};

    /* Best-effort lock of sensitive buffers into RAM to prevent paging to swap */
    (void)sodium_mlock(session_key, sizeof(session_key));
    (void)sodium_mlock(master_pass, sizeof(master_pass));
    (void)sodium_mlock(confirm_pass, sizeof(confirm_pass));

    cli_print_banner();

    unsigned int failed_attempts = 0;

    /* Authentication loop */
    while (current_user_id < 0 && !g_stop_requested) {
        AuthCommand auth = cli_get_auth_command(current_username, sizeof(current_username));
        if (g_stop_requested) {
            break;
        }

        if (auth == AUTH_CMD_LOGIN) {
            if (read_hidden_input("Master password: ", master_pass, sizeof(master_pass)) != 0) {
                printf("[-] Password input failed or exceeded maximum length.\n");
                sodium_memzero(master_pass, sizeof(master_pass));
                continue;
            }

            int uid = -1;
            char auth_hash[crypto_pwhash_STRBYTES] = {0};
            unsigned char kdf_salt[crypto_pwhash_SALTBYTES] = {0};

            int user_found = (db_get_user(current_username, &uid, auth_hash, kdf_salt) == 0);
            int authenticated = 0;

            if (user_found) {
                if (crypto_verify_pass(auth_hash, master_pass) == 0 &&
                    crypto_derive_key(master_pass, kdf_salt, session_key) == 0) {
                    authenticated = 1;
                }
            } else {
                /* Mitigate username-enumeration timing side-channel */
                crypto_dummy_verify(master_pass);
            }

            sodium_memzero(master_pass, sizeof(master_pass));
            sodium_memzero(auth_hash, sizeof(auth_hash));
            sodium_memzero(kdf_salt, sizeof(kdf_salt));

            if (authenticated) {
                current_user_id = uid;
                failed_attempts = 0;
                log_event("LOGIN", current_username, current_user_id,
                          "SUCCESS", "vault unlocked");
                printf("[+] Vault unlocked for '%s'.\n", current_username);
                cli_print_vault_menu();
            } else {
                failed_attempts++;
                log_event("LOGIN", current_username, -1,
                          "FAILURE", "invalid credentials");
                printf("[-] Invalid username or master password.\n");

                if (failed_attempts >= MAX_FAILED_LOGINS) {
                    log_event("AUTH_LOCKOUT", current_username, -1,
                              "LOCKED", "maximum consecutive login failures reached");
                    printf("[-] Too many failed attempts. Pausing for %d seconds...\n",
                           LOCKOUT_SECONDS);
                    sleep(LOCKOUT_SECONDS);
                    failed_attempts = 0;
                } else {
                    /* Exponential backoff: 1s, 2s, 4s, 8s */
                    unsigned int delay = 1U << (failed_attempts - 1U);
                    sleep(delay);
                }
            }

        } else if (auth == AUTH_CMD_SIGNUP) {
            if (read_hidden_input("New master password: ", master_pass, sizeof(master_pass)) != 0) {
                printf("[-] Password input failed or exceeded maximum length.\n");
                sodium_memzero(master_pass, sizeof(master_pass));
                continue;
            }

            if (validate_master_password(master_pass) != 0) {
                printf("[-] Master password must be %d-%d printable ASCII characters and include "
                       "uppercase, lowercase, digit, and special character.\n",
                       MIN_MASTER_PASS_LEN, MAX_PASS_LEN - 1);
                log_event("SIGNUP", current_username, -1,
                          "FAILURE", "weak master password rejected");
                sodium_memzero(master_pass, sizeof(master_pass));
                continue;
            }

            if (read_hidden_input("Confirm master password: ", confirm_pass, sizeof(confirm_pass)) != 0 ||
                sodium_memcmp(master_pass, confirm_pass, sizeof(master_pass)) != 0) {
                printf("[-] Passwords do not match.\n");
                sodium_memzero(master_pass, sizeof(master_pass));
                sodium_memzero(confirm_pass, sizeof(confirm_pass));
                continue;
            }
            sodium_memzero(confirm_pass, sizeof(confirm_pass));

            char auth_hash[crypto_pwhash_STRBYTES] = {0};
            unsigned char kdf_salt[crypto_pwhash_SALTBYTES] = {0};
            randombytes_buf(kdf_salt, sizeof(kdf_salt));

            if (crypto_hash_pass(master_pass, auth_hash) == 0 &&
                db_create_user(current_username, auth_hash, kdf_salt) == 0) {
                log_event("SIGNUP", current_username, -1, "SUCCESS", "account created");
                printf("[+] Account '%s' created. You can now LOGIN %s.\n",
                       current_username, current_username);
            } else {
                log_event("SIGNUP", current_username, -1,
                          "FAILURE", "account creation failed");
                printf("[-] Could not create account (username may already exist).\n");
            }

            sodium_memzero(master_pass, sizeof(master_pass));
            sodium_memzero(auth_hash, sizeof(auth_hash));
            sodium_memzero(kdf_salt, sizeof(kdf_salt));

        } else if (auth == AUTH_CMD_EXIT) {
            printf("Exiting.\n");
            break;
        }
    }

    /* Authenticated vault loop */
    int running = (current_user_id > 0 && !g_stop_requested);
    while (running && !g_stop_requested) {
        VaultCommand cmd = cli_get_vault_command(url, sizeof(url),
                                                 entry_username, sizeof(entry_username));
        if (g_stop_requested) {
            break;
        }

        switch (cmd) {
            case VAULT_CMD_ADD: {
                char service_pass[MAX_PASS_LEN] = {0};
                (void)sodium_mlock(service_pass, sizeof(service_pass));

                if (read_hidden_input("Service password: ", service_pass, sizeof(service_pass)) != 0 ||
                    validate_service_password(service_pass) != 0) {
                    printf("[-] Invalid service password (1-%d printable ASCII characters).\n",
                           MAX_PASS_LEN - 1);
                    log_event("VAULT_ADD", current_username, current_user_id,
                              "FAILURE", "invalid service password");
                    sodium_memzero(service_pass, sizeof(service_pass));
                    (void)sodium_munlock(service_pass, sizeof(service_pass));
                    break;
                }

                size_t pass_len = strlen(service_pass);
                unsigned char nonce[crypto_secretbox_NONCEBYTES] = {0};
                unsigned char ciphertext[DB_MAX_CIPHER] = {0};

                if (crypto_encrypt_vault_entry((const unsigned char *)service_pass, pass_len,
                                               session_key, nonce, ciphertext) == 0 &&
                    db_add_entry(current_user_id, url, entry_username, nonce, ciphertext,
                                 pass_len + crypto_secretbox_MACBYTES) == 0) {
                    printf("[+] Added entry for %s (%s).\n", url, entry_username);
                    log_event("VAULT_ADD", current_username, current_user_id,
                              "SUCCESS", url);
                } else {
                    printf("[-] Failed to store entry (URL may already exist; use UPDATE).\n");
                    log_event("VAULT_ADD", current_username, current_user_id,
                              "FAILURE", url);
                }

                sodium_memzero(service_pass, sizeof(service_pass));
                (void)sodium_munlock(service_pass, sizeof(service_pass));
                sodium_memzero(ciphertext, sizeof(ciphertext));
                sodium_memzero(nonce, sizeof(nonce));
                break;
            }

            case VAULT_CMD_GET: {
                char out_user[DB_MAX_TEXT] = {0};
                unsigned char nonce[crypto_secretbox_NONCEBYTES] = {0};
                unsigned char ciphertext[DB_MAX_CIPHER] = {0};
                size_t cipher_len = 0;

                if (db_get_entry(current_user_id, url, out_user, sizeof(out_user),
                                 nonce, ciphertext, &cipher_len) != 0) {
                    printf("[-] No entry found for %s.\n", url);
                    log_event("VAULT_GET", current_username, current_user_id,
                              "FAILURE", url);
                    break;
                }

                unsigned char decrypted[DB_MAX_TEXT + 1] = {0};
                (void)sodium_mlock(decrypted, sizeof(decrypted));

                if (crypto_decrypt_vault_entry(ciphertext, cipher_len, nonce,
                                               session_key, decrypted) == 0) {
                    size_t plain_len = cipher_len - crypto_secretbox_MACBYTES;
                    decrypted[plain_len] = '\0';

                    printf("URL:      %s\n", url);
                    printf("Username: %s\n", out_user);

                    if (cli_copy_to_clipboard((const char *)decrypted,
                                              CLIPBOARD_CLEAR_SECONDS) == 0) {
                        printf("[+] Password copied to clipboard (auto-clears in %ds).\n",
                               CLIPBOARD_CLEAR_SECONDS);
                        log_event("VAULT_GET", current_username, current_user_id,
                                  "SUCCESS", url);
                    } else {
                        printf("[-] No clipboard utility available (install wl-copy, xclip, or xsel). "
                               "Password not printed to terminal.\n");
                        log_event("VAULT_GET", current_username, current_user_id,
                                  "FAILURE", "clipboard unavailable");
                    }
                } else {
                    printf("[-] Decryption failed: integrity check error.\n");
                    log_event("VAULT_GET", current_username, current_user_id,
                              "FAILURE", "decryption integrity failure");
                }

                sodium_memzero(decrypted, sizeof(decrypted));
                (void)sodium_munlock(decrypted, sizeof(decrypted));
                sodium_memzero(ciphertext, sizeof(ciphertext));
                sodium_memzero(nonce, sizeof(nonce));
                break;
            }

            case VAULT_CMD_UPDATE: {
                if (!db_entry_exists(current_user_id, url)) {
                    printf("[-] No entry found for %s.\n", url);
                    log_event("VAULT_UPDATE", current_username, current_user_id,
                              "FAILURE", "entry not found");
                    break;
                }

                char service_pass[MAX_PASS_LEN] = {0};
                (void)sodium_mlock(service_pass, sizeof(service_pass));

                if (read_hidden_input("New service password: ", service_pass, sizeof(service_pass)) != 0 ||
                    validate_service_password(service_pass) != 0) {
                    printf("[-] Invalid service password (1-%d printable ASCII characters).\n",
                           MAX_PASS_LEN - 1);
                    log_event("VAULT_UPDATE", current_username, current_user_id,
                              "FAILURE", "invalid service password");
                    sodium_memzero(service_pass, sizeof(service_pass));
                    (void)sodium_munlock(service_pass, sizeof(service_pass));
                    break;
                }

                size_t pass_len = strlen(service_pass);
                unsigned char nonce[crypto_secretbox_NONCEBYTES] = {0};
                unsigned char ciphertext[DB_MAX_CIPHER] = {0};

                /* Always generates a fresh random nonce via crypto_encrypt_vault_entry */
                if (crypto_encrypt_vault_entry((const unsigned char *)service_pass, pass_len,
                                               session_key, nonce, ciphertext) == 0 &&
                    db_update_entry(current_user_id, url, entry_username, nonce, ciphertext,
                                    pass_len + crypto_secretbox_MACBYTES) == 0) {
                    printf("[+] Updated entry for %s (%s).\n", url, entry_username);
                    log_event("VAULT_UPDATE", current_username, current_user_id,
                              "SUCCESS", url);
                } else {
                    printf("[-] Failed to update entry.\n");
                    log_event("VAULT_UPDATE", current_username, current_user_id,
                              "FAILURE", url);
                }

                sodium_memzero(service_pass, sizeof(service_pass));
                (void)sodium_munlock(service_pass, sizeof(service_pass));
                sodium_memzero(ciphertext, sizeof(ciphertext));
                sodium_memzero(nonce, sizeof(nonce));
                break;
            }

            case VAULT_CMD_DEL: {
                if (db_del_entry(current_user_id, url) == 0) {
                    printf("[+] Deleted entry for %s.\n", url);
                    log_event("VAULT_DEL", current_username, current_user_id,
                              "SUCCESS", url);
                } else {
                    printf("[-] No entry found for %s.\n", url);
                    log_event("VAULT_DEL", current_username, current_user_id,
                              "FAILURE", url);
                }
                break;
            }

            case VAULT_CMD_LIST: {
                if (db_list_entries(current_user_id) == 0) {
                    log_event("VAULT_LIST", current_username, current_user_id,
                              "SUCCESS", "listed entries");
                } else {
                    printf("[-] Failed to list entries.\n");
                    log_event("VAULT_LIST", current_username, current_user_id,
                              "FAILURE", "list query failed");
                }
                break;
            }

            case VAULT_CMD_HELP:
                cli_print_vault_menu();
                break;

            case VAULT_CMD_EXIT:
                printf("Locking vault. Goodbye!\n");
                running = 0;
                break;

            case VAULT_CMD_INVALID:
            default:
                break;
        }
    }

    if (current_user_id > 0) {
        log_event("LOGOUT", current_username, current_user_id,
                  "SUCCESS", g_stop_requested ? "interrupted by signal" : "vault locked");
    } else {
        log_event("EXIT", "-", -1, "SUCCESS",
                  g_stop_requested ? "interrupted by signal" : "exited before login");
    }

    /* Secure cleanup of all sensitive state */
    sodium_memzero(master_pass, sizeof(master_pass));
    (void)sodium_munlock(master_pass, sizeof(master_pass));
    sodium_memzero(confirm_pass, sizeof(confirm_pass));
    (void)sodium_munlock(confirm_pass, sizeof(confirm_pass));
    sodium_memzero(session_key, sizeof(session_key));
    (void)sodium_munlock(session_key, sizeof(session_key));

    cli_restore_terminal();
    db_close();
    log_close();
    return 0;
}
