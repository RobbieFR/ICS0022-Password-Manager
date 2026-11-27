#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "crypto.h"
#include "db.h"
#include "log.h"
#include "validation.h"

static int g_tests_run = 0;
static int g_tests_passed = 0;
static int g_tests_failed = 0;

#define ASSERT_TRUE(cond, msg)                                                 \
    do {                                                                       \
        g_tests_run++;                                                         \
        if (cond) {                                                            \
            g_tests_passed++;                                                  \
        } else {                                                               \
            g_tests_failed++;                                                  \
            fprintf(stderr, "  [FAIL] %s:%d: %s\n", __FILE__, __LINE__, msg);  \
        }                                                                      \
    } while (0)

static void print_section(const char *name) {
    printf("\n=== %s ===\n", name);
}

/* -------------------------------------------------------------------------- */
/* 1. Input Validation & Sanitization Edge Cases                              */
/* -------------------------------------------------------------------------- */
static void test_input_validation(void) {
    print_section("1. Input Validation & Sanitization Edge Cases");

    /* Usernames: valid cases and boundary lengths */
    ASSERT_TRUE(validate_username("abc") == 0, "min-length (3) username accepted");
    ASSERT_TRUE(validate_username("robbie.berlioz_26-1@taltech.ee") == 0,
                "standard username with allowed punctuation accepted");

    char max_user[MAX_USERNAME_LEN];
    memset(max_user, 'a', MAX_USERNAME_LEN - 1);
    max_user[MAX_USERNAME_LEN - 1] = '\0';
    ASSERT_TRUE(validate_username(max_user) == 0, "max-length (63) username accepted");

    /* Usernames: invalid / attack cases */
    char over_user[MAX_USERNAME_LEN + 2];
    memset(over_user, 'a', MAX_USERNAME_LEN);
    over_user[MAX_USERNAME_LEN] = '\0';

    ASSERT_TRUE(validate_username(NULL) != 0, "NULL username rejected");
    ASSERT_TRUE(validate_username("") != 0, "empty username rejected");
    ASSERT_TRUE(validate_username("ab") != 0, "too-short (2) username rejected");
    ASSERT_TRUE(validate_username(over_user) != 0, "oversized (64) username rejected");
    ASSERT_TRUE(validate_username("admin' OR '1'='1") != 0, "SQLi username rejected");
    ASSERT_TRUE(validate_username("john doe") != 0, "username with space rejected");
    ASSERT_TRUE(validate_username("alice;rm -rf") != 0, "command-injection username rejected");
    ASSERT_TRUE(validate_username("alice\nbob") != 0, "newline injection username rejected");
    ASSERT_TRUE(validate_username("\x1b[31mroot") != 0, "ANSI escape username rejected");

    /* URLs: valid cases and boundary lengths */
    ASSERT_TRUE(validate_url("a") == 0, "min-length (1) URL accepted");
    ASSERT_TRUE(validate_url("https://github.com/RobbieFR/ICS0022") == 0,
                "standard HTTPS URL accepted");

    char max_url[MAX_URL_LEN];
    memset(max_url, 'u', MAX_URL_LEN - 1);
    max_url[MAX_URL_LEN - 1] = '\0';
    ASSERT_TRUE(validate_url(max_url) == 0, "max-length (127) URL accepted");

    /* URLs: invalid / attack cases */
    char over_url[MAX_URL_LEN + 2];
    memset(over_url, 'u', MAX_URL_LEN);
    over_url[MAX_URL_LEN] = '\0';

    ASSERT_TRUE(validate_url(NULL) != 0, "NULL URL rejected");
    ASSERT_TRUE(validate_url("") != 0, "empty URL rejected");
    ASSERT_TRUE(validate_url(over_url) != 0, "oversized (128) URL rejected");
    ASSERT_TRUE(validate_url("https://bad site.com") != 0, "URL with space rejected");
    ASSERT_TRUE(validate_url("https://evil.com';DROP TABLE users;--") != 0,
                "SQLi URL with single quote/semicolon rejected");
    ASSERT_TRUE(validate_url("https://evil.com\"injected") != 0,
                "URL with double quote rejected");
    ASSERT_TRUE(validate_url("https://evil.com`id`") != 0,
                "URL with backtick rejected");
    ASSERT_TRUE(validate_url("https://evil.com\\path") != 0,
                "URL with backslash rejected");
    ASSERT_TRUE(validate_url("https://evil.com\r\n") != 0,
                "URL with CRLF rejected");

    /* Master Passwords: complexity & length policy (>= 12 chars) */
    ASSERT_TRUE(validate_master_password("Aa1!bbbbbbbb") == 0,
                "min-length (12) strong master password accepted");
    ASSERT_TRUE(validate_master_password("Str0ng!Master#2026") == 0,
                "strong master password accepted");

    char max_pass[MAX_PASS_LEN];
    memset(max_pass, 'a', MAX_PASS_LEN - 1);
    max_pass[0] = 'A';
    max_pass[1] = '1';
    max_pass[2] = '!';
    max_pass[MAX_PASS_LEN - 1] = '\0';
    ASSERT_TRUE(validate_master_password(max_pass) == 0,
                "max-length (127) strong master password accepted");

    char over_pass[MAX_PASS_LEN + 2];
    memset(over_pass, 'a', MAX_PASS_LEN);
    over_pass[0] = 'A';
    over_pass[1] = '1';
    over_pass[2] = '!';
    over_pass[MAX_PASS_LEN] = '\0';

    ASSERT_TRUE(validate_master_password(NULL) != 0, "NULL master password rejected");
    ASSERT_TRUE(validate_master_password("Aa1!bbbbbbb") != 0,
                "11-char master password rejected");
    ASSERT_TRUE(validate_master_password(over_pass) != 0,
                "oversized (128) master password rejected");
    ASSERT_TRUE(validate_master_password("alllowercase1!") != 0,
                "master password without uppercase rejected");
    ASSERT_TRUE(validate_master_password("ALLUPPERCASE1!") != 0,
                "master password without lowercase rejected");
    ASSERT_TRUE(validate_master_password("NoDigitsHere!!") != 0,
                "master password without digit rejected");
    ASSERT_TRUE(validate_master_password("NoSpecialChar123") != 0,
                "master password without special char rejected");
    ASSERT_TRUE(validate_master_password("Aa1!bbbb\nbbb") != 0,
                "master password with control character rejected");

    /* Service Passwords */
    ASSERT_TRUE(validate_service_password("x") == 0, "1-char service password accepted");
    ASSERT_TRUE(validate_service_password("S3rv!ce P@ss") == 0,
                "service password with printable space accepted");
    ASSERT_TRUE(validate_service_password(NULL) != 0, "NULL service password rejected");
    ASSERT_TRUE(validate_service_password("") != 0, "empty service password rejected");
    ASSERT_TRUE(validate_service_password(over_pass) != 0,
                "oversized (128) service password rejected");
    ASSERT_TRUE(validate_service_password("bad\tpass") != 0,
                "service password with tab/control char rejected");

    /* Log Sanitization (JSON injection prevention) */
    char sanitized[64];
    sanitize_for_log("user\"}\n{\"fake\":\"1\\2", sanitized, sizeof(sanitized));
    ASSERT_TRUE(strchr(sanitized, '"') == NULL &&
                strchr(sanitized, '\\') == NULL &&
                strchr(sanitized, '\n') == NULL,
                "sanitize_for_log strips quotes, backslashes, and newlines");

    printf("  Validation checks completed.\n");
}

/* -------------------------------------------------------------------------- */
/* 2. Cryptographic Correctness, AEAD Tampering & Key Derivation              */
/* -------------------------------------------------------------------------- */
static void test_cryptography(void) {
    print_section("2. Cryptographic Correctness & Integrity (Argon2id + XSalsa20-Poly1305)");

    ASSERT_TRUE(crypto_init() == 0, "crypto_init succeeds");

    const char *master_pw = "Master#Secret2026!";
    char hash1[crypto_pwhash_STRBYTES] = {0};
    char hash2[crypto_pwhash_STRBYTES] = {0};

    ASSERT_TRUE(crypto_hash_pass(master_pw, hash1) == 0, "crypto_hash_pass succeeds");
    ASSERT_TRUE(crypto_hash_pass(master_pw, hash2) == 0, "second crypto_hash_pass succeeds");
    ASSERT_TRUE(strcmp(hash1, hash2) != 0, "Argon2id hashes use unique random salts");
    ASSERT_TRUE(crypto_verify_pass(hash1, master_pw) == 0,
                "crypto_verify_pass accepts correct password");
    ASSERT_TRUE(crypto_verify_pass(hash1, "Wrong#Password2026!") != 0,
                "crypto_verify_pass rejects wrong password");
    ASSERT_TRUE(crypto_verify_pass(NULL, master_pw) != 0,
                "crypto_verify_pass rejects NULL hash");

    /* Dummy verification should run cleanly */
    crypto_dummy_verify("NonExistentUserPass!1");

    /* Key derivation */
    unsigned char salt1[crypto_pwhash_SALTBYTES];
    unsigned char salt2[crypto_pwhash_SALTBYTES];
    randombytes_buf(salt1, sizeof(salt1));
    randombytes_buf(salt2, sizeof(salt2));

    unsigned char key1a[crypto_secretbox_KEYBYTES] = {0};
    unsigned char key1b[crypto_secretbox_KEYBYTES] = {0};
    unsigned char key2[crypto_secretbox_KEYBYTES] = {0};

    ASSERT_TRUE(crypto_derive_key(master_pw, salt1, key1a) == 0, "derive key1a succeeds");
    ASSERT_TRUE(crypto_derive_key(master_pw, salt1, key1b) == 0, "derive key1b succeeds");
    ASSERT_TRUE(crypto_derive_key(master_pw, salt2, key2) == 0, "derive key2 succeeds");

    ASSERT_TRUE(sodium_memcmp(key1a, key1b, sizeof(key1a)) == 0,
                "same password + same salt yields identical key");
    ASSERT_TRUE(sodium_memcmp(key1a, key2, sizeof(key1a)) != 0,
                "different salt yields different key");

    /* Authenticated encryption round-trip */
    const char *secret = "GitHub_Token_99!@#";
    size_t secret_len = strlen(secret);
    size_t cipher_len = secret_len + crypto_secretbox_MACBYTES;

    unsigned char nonce1[crypto_secretbox_NONCEBYTES] = {0};
    unsigned char nonce2[crypto_secretbox_NONCEBYTES] = {0};
    unsigned char cipher1[DB_MAX_CIPHER] = {0};
    unsigned char cipher2[DB_MAX_CIPHER] = {0};
    unsigned char decrypted[DB_MAX_TEXT + 1] = {0};

    ASSERT_TRUE(crypto_encrypt_vault_entry((const unsigned char *)secret, secret_len,
                                           key1a, nonce1, cipher1) == 0,
                "encrypt entry 1 succeeds");
    ASSERT_TRUE(crypto_encrypt_vault_entry((const unsigned char *)secret, secret_len,
                                           key1a, nonce2, cipher2) == 0,
                "encrypt entry 2 succeeds");
    ASSERT_TRUE(memcmp(nonce1, nonce2, sizeof(nonce1)) != 0,
                "each encryption generates a fresh random nonce");
    ASSERT_TRUE(memcmp(cipher1, cipher2, cipher_len) != 0,
                "identical plaintexts produce distinct ciphertexts");

    ASSERT_TRUE(crypto_decrypt_vault_entry(cipher1, cipher_len, nonce1,
                                           key1a, decrypted) == 0,
                "decrypt with valid key/nonce succeeds");
    decrypted[secret_len] = '\0';
    ASSERT_TRUE(strcmp((const char *)decrypted, secret) == 0,
                "decrypted plaintext matches original secret");

    /* Tampering and wrong-key rejection (Poly1305 authentication) */
    unsigned char tampered_cipher[DB_MAX_CIPHER];
    memcpy(tampered_cipher, cipher1, cipher_len);
    tampered_cipher[0] ^= 0x01;
    ASSERT_TRUE(crypto_decrypt_vault_entry(tampered_cipher, cipher_len, nonce1,
                                           key1a, decrypted) != 0,
                "tampered ciphertext fails Poly1305 MAC check");

    unsigned char tampered_nonce[crypto_secretbox_NONCEBYTES];
    memcpy(tampered_nonce, nonce1, sizeof(nonce1));
    tampered_nonce[0] ^= 0x80;
    ASSERT_TRUE(crypto_decrypt_vault_entry(cipher1, cipher_len, tampered_nonce,
                                           key1a, decrypted) != 0,
                "tampered nonce fails decryption");

    ASSERT_TRUE(crypto_decrypt_vault_entry(cipher1, cipher_len, nonce1,
                                           key2, decrypted) != 0,
                "wrong session key fails decryption");

    ASSERT_TRUE(crypto_decrypt_vault_entry(cipher1, crypto_secretbox_MACBYTES, nonce1,
                                           key1a, decrypted) != 0,
                "truncated ciphertext (<= MACBYTES) safely rejected");

    ASSERT_TRUE(crypto_encrypt_vault_entry((const unsigned char *)"", 0,
                                           key1a, nonce1, cipher1) != 0,
                "zero-length plaintext encryption rejected");

    sodium_memzero(hash1, sizeof(hash1));
    sodium_memzero(hash2, sizeof(hash2));
    sodium_memzero(key1a, sizeof(key1a));
    sodium_memzero(key1b, sizeof(key1b));
    sodium_memzero(key2, sizeof(key2));
    sodium_memzero(decrypted, sizeof(decrypted));

    printf("  Cryptography checks completed.\n");
}

/* -------------------------------------------------------------------------- */
/* 3. Database CRUD, Permissions, SQLi Safety & Per-User Access Control       */
/* -------------------------------------------------------------------------- */
static void test_database_and_access_control(void) {
    print_section("3. Database CRUD, Permissions & Per-User Access Control");

    const char *test_db = "/tmp/ics0022_test_vault.db";
    unlink(test_db);

    ASSERT_TRUE(db_init(test_db) == 0, "db_init creates database successfully");

    struct stat st;
    ASSERT_TRUE(stat(test_db, &st) == 0 && (st.st_mode & 0777) == 0600,
                "database file permissions enforced to 0600");

    /* Create two independent users: alice and bob */
    unsigned char salt_a[crypto_pwhash_SALTBYTES], salt_b[crypto_pwhash_SALTBYTES];
    randombytes_buf(salt_a, sizeof(salt_a));
    randombytes_buf(salt_b, sizeof(salt_b));

    char hash_a[crypto_pwhash_STRBYTES] = {0};
    char hash_b[crypto_pwhash_STRBYTES] = {0};
    ASSERT_TRUE(crypto_hash_pass("Alice#Pass2026!", hash_a) == 0, "hash alice");
    ASSERT_TRUE(crypto_hash_pass("Bob#Secret2026!", hash_b) == 0, "hash bob");

    ASSERT_TRUE(db_create_user("alice", hash_a, salt_a) == 0, "create user alice");
    ASSERT_TRUE(db_create_user("alice", hash_a, salt_a) != 0,
                "duplicate username alice rejected");
    ASSERT_TRUE(db_create_user("bob", hash_b, salt_b) == 0, "create user bob");

    int uid_a = -1, uid_b = -1;
    char fetched_hash[crypto_pwhash_STRBYTES] = {0};
    unsigned char fetched_salt[crypto_pwhash_SALTBYTES] = {0};

    ASSERT_TRUE(db_get_user("alice", &uid_a, fetched_hash, fetched_salt) == 0 && uid_a > 0,
                "fetch user alice succeeds");
    ASSERT_TRUE(db_get_user("bob", &uid_b, fetched_hash, fetched_salt) == 0 &&
                uid_b > 0 && uid_b != uid_a,
                "fetch user bob succeeds with distinct user_id");

    /* Parameterized query check against SQL injection */
    int sqli_uid = -1;
    ASSERT_TRUE(db_get_user("' OR '1'='1", &sqli_uid, fetched_hash, fetched_salt) != 0,
                "SQL injection payload in db_get_user returns no user");

    /* Derive keys for alice and bob */
    unsigned char key_a[crypto_secretbox_KEYBYTES] = {0};
    unsigned char key_b[crypto_secretbox_KEYBYTES] = {0};
    ASSERT_TRUE(crypto_derive_key("Alice#Pass2026!", salt_a, key_a) == 0, "derive key_a");
    ASSERT_TRUE(crypto_derive_key("Bob#Secret2026!", salt_b, key_b) == 0, "derive key_b");

    /* Alice adds an entry */
    const char *pw1 = "AliceGitHubPass!1";
    size_t pw1_len = strlen(pw1);
    unsigned char nonce_a1[crypto_secretbox_NONCEBYTES] = {0};
    unsigned char cipher_a1[DB_MAX_CIPHER] = {0};
    ASSERT_TRUE(crypto_encrypt_vault_entry((const unsigned char *)pw1, pw1_len,
                                           key_a, nonce_a1, cipher_a1) == 0,
                "encrypt alice entry");
    ASSERT_TRUE(db_add_entry(uid_a, "github.com", "alice_gh", nonce_a1,
                             cipher_a1, pw1_len + crypto_secretbox_MACBYTES) == 0,
                "db_add_entry succeeds for alice");
    ASSERT_TRUE(db_add_entry(uid_a, "github.com", "alice_gh2", nonce_a1,
                             cipher_a1, pw1_len + crypto_secretbox_MACBYTES) != 0,
                "duplicate (user_id, url) rejected by UNIQUE constraint");

    /* Per-user access control: Bob cannot read, check, update, or delete Alice's entry */
    char out_user[DB_MAX_TEXT] = {0};
    unsigned char out_nonce[crypto_secretbox_NONCEBYTES] = {0};
    unsigned char out_cipher[DB_MAX_CIPHER] = {0};
    size_t out_cipher_len = 0;

    ASSERT_TRUE(db_entry_exists(uid_a, "github.com") == 1,
                "db_entry_exists returns 1 for owner alice");
    ASSERT_TRUE(db_entry_exists(uid_b, "github.com") == 0,
                "db_entry_exists returns 0 for non-owner bob");
    ASSERT_TRUE(db_get_entry(uid_b, "github.com", out_user, sizeof(out_user),
                             out_nonce, out_cipher, &out_cipher_len) != 0,
                "bob cannot GET alice's entry");
    ASSERT_TRUE(db_update_entry(uid_b, "github.com", "hijacked", nonce_a1,
                                cipher_a1, pw1_len + crypto_secretbox_MACBYTES) != 0,
                "bob cannot UPDATE alice's entry");
    ASSERT_TRUE(db_del_entry(uid_b, "github.com") != 0,
                "bob cannot DEL alice's entry");

    /* Bob can create his own independent entry for the same URL */
    const char *pw_bob = "BobGitHubPass!2";
    size_t pw_bob_len = strlen(pw_bob);
    unsigned char nonce_b[crypto_secretbox_NONCEBYTES] = {0};
    unsigned char cipher_b[DB_MAX_CIPHER] = {0};
    ASSERT_TRUE(crypto_encrypt_vault_entry((const unsigned char *)pw_bob, pw_bob_len,
                                           key_b, nonce_b, cipher_b) == 0,
                "encrypt bob entry");
    ASSERT_TRUE(db_add_entry(uid_b, "github.com", "bob_gh", nonce_b,
                             cipher_b, pw_bob_len + crypto_secretbox_MACBYTES) == 0,
                "bob can store his own entry for same URL");

    /* Alice updates her own entry with fresh nonce and password */
    const char *pw2 = "AliceUpdatedPass!99";
    size_t pw2_len = strlen(pw2);
    unsigned char nonce_a2[crypto_secretbox_NONCEBYTES] = {0};
    unsigned char cipher_a2[DB_MAX_CIPHER] = {0};
    ASSERT_TRUE(crypto_encrypt_vault_entry((const unsigned char *)pw2, pw2_len,
                                           key_a, nonce_a2, cipher_a2) == 0,
                "encrypt updated alice entry");
    ASSERT_TRUE(db_update_entry(uid_a, "github.com", "alice_new", nonce_a2,
                                cipher_a2, pw2_len + crypto_secretbox_MACBYTES) == 0,
                "alice updates her own entry");

    ASSERT_TRUE(db_get_entry(uid_a, "github.com", out_user, sizeof(out_user),
                             out_nonce, out_cipher, &out_cipher_len) == 0,
                "alice fetches updated entry");
    ASSERT_TRUE(strcmp(out_user, "alice_new") == 0, "updated username persisted");
    ASSERT_TRUE(memcmp(out_nonce, nonce_a1, sizeof(out_nonce)) != 0,
                "updated entry stored with fresh nonce");

    unsigned char decrypted[DB_MAX_TEXT + 1] = {0};
    ASSERT_TRUE(crypto_decrypt_vault_entry(out_cipher, out_cipher_len, out_nonce,
                                           key_a, decrypted) == 0,
                "decrypt updated alice entry succeeds");
    decrypted[out_cipher_len - crypto_secretbox_MACBYTES] = '\0';
    ASSERT_TRUE(strcmp((const char *)decrypted, pw2) == 0,
                "updated password matches new secret");

    /* Alice deletes her entry; Bob's entry must remain unaffected */
    ASSERT_TRUE(db_del_entry(uid_a, "github.com") == 0, "alice deletes her entry");
    ASSERT_TRUE(db_del_entry(uid_a, "github.com") != 0, "deleting already-deleted entry fails");
    ASSERT_TRUE(db_entry_exists(uid_b, "github.com") == 1,
                "bob's entry remains intact after alice deletes hers");

    /* Invalid user_id / NULL safety */
    ASSERT_TRUE(db_del_entry(0, "github.com") != 0, "user_id=0 rejected");
    ASSERT_TRUE(db_del_entry(-5, "github.com") != 0, "negative user_id rejected");
    ASSERT_TRUE(db_list_entries(-1) != 0, "db_list_entries rejects invalid user_id");

    sodium_memzero(hash_a, sizeof(hash_a));
    sodium_memzero(hash_b, sizeof(hash_b));
    sodium_memzero(fetched_hash, sizeof(fetched_hash));
    sodium_memzero(key_a, sizeof(key_a));
    sodium_memzero(key_b, sizeof(key_b));
    sodium_memzero(decrypted, sizeof(decrypted));

    db_close();
    unlink(test_db);

    printf("  Database and access-control checks completed.\n");
}

/* -------------------------------------------------------------------------- */
/* 4. Structured Logging & Secret-Leak Verification                           */
/* -------------------------------------------------------------------------- */
static void test_structured_logging(void) {
    print_section("4. Structured Logging, Permissions & Log Injection Defense");

    const char *test_log = "/tmp/ics0022_test_vault.log";
    unlink(test_log);

    ASSERT_TRUE(log_init(test_log) == 0, "log_init creates log file");

    struct stat st;
    ASSERT_TRUE(stat(test_log, &st) == 0 && (st.st_mode & 0777) == 0600,
                "log file permissions enforced to 0600");

    log_event("LOGIN", "alice", 1, "SUCCESS", "vault unlocked");
    log_event("VAULT_ADD", "alice\"}\n{\"event\":\"FORGED", 1, "SUCCESS", "github.com");
    log_close();

    FILE *fp = fopen(test_log, "r");
    ASSERT_TRUE(fp != NULL, "log file readable by owner");

    if (fp) {
        char line[512];
        int line_count = 0;
        int valid_structure = 1;
        int forged_line_found = 0;

        while (fgets(line, sizeof(line), fp) != NULL) {
            line_count++;
            size_t len = strlen(line);
            if (strncmp(line, "{\"timestamp\":\"", 14) != 0 ||
                len < 2 || line[len - 2] != '}') {
                valid_structure = 0;
            }
            if (strstr(line, "\"event\":\"FORGED\"") != NULL) {
                forged_line_found = 1;
            }
        }
        fclose(fp);

        ASSERT_TRUE(line_count == 2,
                    "newline payload did not inject an extra log line (exact 2 lines)");
        ASSERT_TRUE(valid_structure == 1,
                    "all log records follow structured JSONL format");
        ASSERT_TRUE(forged_line_found == 0,
                    "JSON injection payload neutralized by sanitize_for_log");
    }

    unlink(test_log);
    printf("  Logging checks completed.\n");
}

/* -------------------------------------------------------------------------- */
/* 5. Secure Memory Handling & Max-Length Boundary Checks                     */
/* -------------------------------------------------------------------------- */
static void test_memory_handling(void) {
    print_section("5. Secure Memory Handling & Boundary Checks");

    /* Verify sodium_memzero zeroes every byte of a secret buffer */
    unsigned char secret_buf[128];
    memset(secret_buf, 0xA5, sizeof(secret_buf));
    sodium_memzero(secret_buf, sizeof(secret_buf));

    int all_zero = 1;
    volatile unsigned char *vptr = secret_buf;
    for (size_t i = 0; i < sizeof(secret_buf); i++) {
        if (vptr[i] != 0) {
            all_zero = 0;
            break;
        }
    }
    ASSERT_TRUE(all_zero == 1, "sodium_memzero completely wipes sensitive buffer");

    /* Verify max-length plaintext (DB_MAX_TEXT = 256 bytes) decrypts safely into DB_MAX_TEXT + 1 */
    unsigned char key[crypto_secretbox_KEYBYTES];
    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    randombytes_buf(key, sizeof(key));

    unsigned char max_plain[DB_MAX_TEXT];
    memset(max_plain, 'Z', DB_MAX_TEXT);
    unsigned char max_cipher[DB_MAX_CIPHER] = {0};
    unsigned char max_decrypted[DB_MAX_TEXT + 1] = {0};

    ASSERT_TRUE(crypto_encrypt_vault_entry(max_plain, DB_MAX_TEXT,
                                           key, nonce, max_cipher) == 0,
                "encrypt max-size (256-byte) payload succeeds");
    ASSERT_TRUE(crypto_decrypt_vault_entry(max_cipher, DB_MAX_CIPHER,
                                           nonce, key, max_decrypted) == 0,
                "decrypt max-size payload succeeds without buffer overflow");
    max_decrypted[DB_MAX_TEXT] = '\0';
    ASSERT_TRUE(memcmp(max_plain, max_decrypted, DB_MAX_TEXT) == 0,
                "max-size decrypted payload matches original byte-for-byte");

    /* Best-effort mlock / munlock check (munlock also wipes memory) */
    unsigned char locked_key[crypto_secretbox_KEYBYTES];
    memset(locked_key, 0x5A, sizeof(locked_key));
    if (sodium_mlock(locked_key, sizeof(locked_key)) == 0) {
        ASSERT_TRUE(sodium_munlock(locked_key, sizeof(locked_key)) == 0,
                    "sodium_mlock/sodium_munlock lifecycle succeeds");
        int wiped = 1;
        volatile unsigned char *lk = locked_key;
        for (size_t i = 0; i < sizeof(locked_key); i++) {
            if (lk[i] != 0) {
                wiped = 0;
                break;
            }
        }
        ASSERT_TRUE(wiped == 1, "sodium_munlock zeroes locked memory region");
    } else {
        sodium_memzero(locked_key, sizeof(locked_key));
        printf("  [INFO] sodium_mlock skipped (insufficient RLIMIT_MEMLOCK in environment).\n");
    }

    sodium_memzero(key, sizeof(key));
    sodium_memzero(max_plain, sizeof(max_plain));
    sodium_memzero(max_decrypted, sizeof(max_decrypted));

    printf("  Memory-handling checks completed.\n");
}

int main(void) {
    if (sodium_init() < 0) {
        fprintf(stderr, "[-] Failed to initialize libsodium.\n");
        return 1;
    }

    test_input_validation();
    test_cryptography();
    test_database_and_access_control();
    test_structured_logging();
    test_memory_handling();

    printf("\n==============================================\n");
    printf("TEST SUMMARY: %d passed, %d failed (%d total)\n",
           g_tests_passed, g_tests_failed, g_tests_run);
    printf("==============================================\n");

    return (g_tests_failed == 0) ? 0 : 1;
}
