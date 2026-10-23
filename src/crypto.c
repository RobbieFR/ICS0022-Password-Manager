// src/crypto.c
#include "crypto.h"
#include <string.h>

int crypto_hash_pass(const char *pass, char out_hash[crypto_pwhash_STRBYTES]) {
    return crypto_pwhash_str(out_hash, pass, strlen(pass), crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE);
}

int crypto_verify_pass(const char *hash, const char *pass) {
    return crypto_pwhash_str_verify(hash, pass, strlen(pass));
}

int crypto_derive_key(const char *pass, const unsigned char salt[crypto_pwhash_SALTBYTES], unsigned char key[crypto_secretbox_KEYBYTES]) {
    return crypto_pwhash(key, crypto_secretbox_KEYBYTES, pass, strlen(pass), salt, 
                         crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE, 
                         crypto_pwhash_ALG_ARGON2ID13);
}

int crypto_encrypt_vault_entry(const unsigned char *message, size_t message_len, const unsigned char key[crypto_secretbox_KEYBYTES], unsigned char nonce[crypto_secretbox_NONCEBYTES], unsigned char *ciphertext) {
    randombytes_buf(nonce, crypto_secretbox_NONCEBYTES);
    return crypto_secretbox_easy(ciphertext, message, message_len, nonce, key);
}

int crypto_decrypt_vault_entry(const unsigned char *ciphertext, size_t ciphertext_len, const unsigned char nonce[crypto_secretbox_NONCEBYTES], const unsigned char key[crypto_secretbox_KEYBYTES], unsigned char *decrypted_message) {
    return crypto_secretbox_open_easy(decrypted_message, ciphertext, ciphertext_len, nonce, key);
}