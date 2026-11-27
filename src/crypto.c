#include "crypto.h"
#include <string.h>

static char dummy_argon2_hash[crypto_pwhash_STRBYTES] = {0};
static int dummy_initialized = 0;

int crypto_init(void) {
    if (dummy_initialized) {
        return 0;
    }
    const char *placeholder = "DummyTimingMitigation!2026";
    if (crypto_pwhash_str(dummy_argon2_hash, placeholder, strlen(placeholder),
                          crypto_pwhash_OPSLIMIT_INTERACTIVE,
                          crypto_pwhash_MEMLIMIT_INTERACTIVE) != 0) {
        return -1;
    }
    dummy_initialized = 1;
    return 0;
}

int crypto_hash_pass(const char *pass, char out_hash[crypto_pwhash_STRBYTES]) {
    if (!pass || !out_hash) {
        return -1;
    }
    return crypto_pwhash_str(out_hash, pass, strlen(pass),
                             crypto_pwhash_OPSLIMIT_INTERACTIVE,
                             crypto_pwhash_MEMLIMIT_INTERACTIVE);
}

int crypto_verify_pass(const char *hash, const char *pass) {
    if (!hash || !pass) {
        return -1;
    }
    return crypto_pwhash_str_verify(hash, pass, strlen(pass));
}

void crypto_dummy_verify(const char *pass) {
    if (!pass || !dummy_initialized) {
        return;
    }
    volatile int rc = crypto_pwhash_str_verify(dummy_argon2_hash, pass, strlen(pass));
    (void)rc;
}

int crypto_derive_key(const char *pass,
                      const unsigned char salt[crypto_pwhash_SALTBYTES],
                      unsigned char key[crypto_secretbox_KEYBYTES]) {
    if (!pass || !salt || !key) {
        return -1;
    }
    return crypto_pwhash(key, crypto_secretbox_KEYBYTES, pass, strlen(pass), salt,
                         crypto_pwhash_OPSLIMIT_INTERACTIVE,
                         crypto_pwhash_MEMLIMIT_INTERACTIVE,
                         crypto_pwhash_ALG_ARGON2ID13);
}

int crypto_encrypt_vault_entry(const unsigned char *message,
                               size_t message_len,
                               const unsigned char key[crypto_secretbox_KEYBYTES],
                               unsigned char nonce[crypto_secretbox_NONCEBYTES],
                               unsigned char *ciphertext) {
    if (!message || !key || !nonce || !ciphertext || message_len == 0) {
        return -1;
    }
    randombytes_buf(nonce, crypto_secretbox_NONCEBYTES);
    return crypto_secretbox_easy(ciphertext, message, message_len, nonce, key);
}

int crypto_decrypt_vault_entry(const unsigned char *ciphertext,
                               size_t ciphertext_len,
                               const unsigned char nonce[crypto_secretbox_NONCEBYTES],
                               const unsigned char key[crypto_secretbox_KEYBYTES],
                               unsigned char *decrypted_message) {
    if (!ciphertext || !nonce || !key || !decrypted_message) {
        return -1;
    }
    if (ciphertext_len <= crypto_secretbox_MACBYTES) {
        return -1;
    }
    return crypto_secretbox_open_easy(decrypted_message, ciphertext,
                                      ciphertext_len, nonce, key);
}
