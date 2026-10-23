#ifndef CRYPTO_H
#define CRYPTO_H

#include <sodium.h>

int crypto_hash_pass(const char *pass, char out_hash[crypto_pwhash_STRBYTES]);
int crypto_verify_pass(const char *hash, const char *pass);

int crypto_derive_key(const char *pass, const unsigned char salt[crypto_pwhash_SALTBYTES], unsigned char key[crypto_secretbox_KEYBYTES]);

int crypto_encrypt_vault_entry(const unsigned char *message, size_t message_len, const unsigned char key[crypto_secretbox_KEYBYTES], unsigned char nonce[crypto_secretbox_NONCEBYTES], unsigned char *ciphertext);
int crypto_decrypt_vault_entry(const unsigned char *ciphertext, size_t ciphertext_len, const unsigned char nonce[crypto_secretbox_NONCEBYTES], const unsigned char key[crypto_secretbox_KEYBYTES], unsigned char *decrypted_message);

#endif