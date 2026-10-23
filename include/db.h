#ifndef DB_H
#define DB_H

#include <stddef.h>
#include <sodium.h>

#define DB_MAX_TEXT 256
#define DB_MAX_CIPHER (DB_MAX_TEXT + crypto_secretbox_MACBYTES)

int db_init(const char *db_path);
void db_close(void);

/* User operations */
int db_create_user(const char *username, const char *auth_hash,
                   const unsigned char kdf_salt[crypto_pwhash_SALTBYTES]);

int db_get_user(const char *username, int *user_id_out,
                char auth_hash_out[crypto_pwhash_STRBYTES],
                unsigned char kdf_salt_out[crypto_pwhash_SALTBYTES]);

/* Vault operations */
int db_add_entry(int user_id, const char *url, const char *username,
                 const unsigned char nonce[crypto_secretbox_NONCEBYTES],
                 const unsigned char *ciphertext, size_t cipher_len);

int db_get_entry(int user_id, const char *url,
                 char *username_out, size_t username_max,
                 unsigned char nonce_out[crypto_secretbox_NONCEBYTES],
                 unsigned char *ciphertext_out, size_t *cipher_len_out);

int db_list_entries(int user_id);

int db_del_entry(int user_id, const char *url);

#endif