#include "db.h"
#include <sqlite3.h>
#include <stdio.h>
#include <string.h>

static sqlite3 *db = NULL;

int db_init(const char *db_path) {
    if (sqlite3_open(db_path, &db) != SQLITE_OK) {
        fprintf(stderr, "Error: Cannot open database.\n");
        return -1;
    }

    const char *schema =
        "CREATE TABLE IF NOT EXISTS users ("
        "    id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "    username TEXT UNIQUE NOT NULL,"
        "    auth_hash TEXT NOT NULL,"
        "    kdf_salt BLOB NOT NULL"
        ");"
        "CREATE TABLE IF NOT EXISTS vault_entries ("
        "    id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "    user_id INTEGER NOT NULL,"
        "    url TEXT NOT NULL,"
        "    username TEXT NOT NULL,"
        "    nonce BLOB NOT NULL,"
        "    ciphertext BLOB NOT NULL,"
        "    FOREIGN KEY(user_id) REFERENCES users(id)"
        ");";

    char *err_msg = NULL;
    if (sqlite3_exec(db, schema, 0, 0, &err_msg) != SQLITE_OK) {
        fprintf(stderr, "Error: Failed to initialize schema.\n");
        sqlite3_free(err_msg);
        return -1;
    }
    return 0;
}

void db_close(void) {
    if (db) {
        sqlite3_close(db);
        db = NULL;
    }
}

int db_create_user(const char *username, const char *auth_hash,
                   const unsigned char kdf_salt[crypto_pwhash_SALTBYTES]) {
    const char *sql = "INSERT INTO users (username, auth_hash, kdf_salt) VALUES (?, ?, ?);";
    sqlite3_stmt *stmt = NULL;

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) return -1;

    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, auth_hash, -1, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 3, kdf_salt, crypto_pwhash_SALTBYTES, SQLITE_STATIC);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    return (rc == SQLITE_DONE) ? 0 : -1;
}

int db_get_user(const char *username, int *user_id_out,
                char auth_hash_out[crypto_pwhash_STRBYTES],
                unsigned char kdf_salt_out[crypto_pwhash_SALTBYTES]) {
    const char *sql = "SELECT id, auth_hash, kdf_salt FROM users WHERE username = ?;";
    sqlite3_stmt *stmt = NULL;

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);

    int rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        *user_id_out = sqlite3_column_int(stmt, 0);

        const char *hash = (const char *)sqlite3_column_text(stmt, 1);
        if (hash) {
            strncpy(auth_hash_out, hash, crypto_pwhash_STRBYTES - 1);
            auth_hash_out[crypto_pwhash_STRBYTES - 1] = '\0';
        }

        const void *salt = sqlite3_column_blob(stmt, 2);
        int salt_len = sqlite3_column_bytes(stmt, 2);
        if (salt && salt_len == crypto_pwhash_SALTBYTES) {
            memcpy(kdf_salt_out, salt, crypto_pwhash_SALTBYTES);
        } else {
            sqlite3_finalize(stmt);
            return -1;
        }

        sqlite3_finalize(stmt);
        return 0;
    }

    sqlite3_finalize(stmt);
    return -1;
}

int db_add_entry(int user_id, const char *url, const char *username,
                 const unsigned char nonce[crypto_secretbox_NONCEBYTES],
                 const unsigned char *ciphertext, size_t cipher_len) {
    const char *sql =
        "INSERT INTO vault_entries (user_id, url, username, nonce, ciphertext) "
        "VALUES (?, ?, ?, ?, ?);";
    sqlite3_stmt *stmt = NULL;

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) return -1;

    sqlite3_bind_int(stmt, 1, user_id);
    sqlite3_bind_text(stmt, 2, url, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, username, -1, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 4, nonce, crypto_secretbox_NONCEBYTES, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 5, ciphertext, (int)cipher_len, SQLITE_STATIC);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    return (rc == SQLITE_DONE) ? 0 : -1;
}

int db_get_entry(int user_id, const char *url,
                 char *username_out, size_t username_max,
                 unsigned char nonce_out[crypto_secretbox_NONCEBYTES],
                 unsigned char *ciphertext_out, size_t *cipher_len_out) {
    const char *sql =
        "SELECT username, nonce, ciphertext FROM vault_entries "
        "WHERE user_id = ? AND url = ? ORDER BY id DESC LIMIT 1;";
    sqlite3_stmt *stmt = NULL;

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) return -1;

    sqlite3_bind_int(stmt, 1, user_id);
    sqlite3_bind_text(stmt, 2, url, -1, SQLITE_STATIC);

    int rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        const char *uname = (const char *)sqlite3_column_text(stmt, 0);
        if (uname) {
            strncpy(username_out, uname, username_max - 1);
            username_out[username_max - 1] = '\0';
        }

        const void *nonce = sqlite3_column_blob(stmt, 1);
        int nonce_len = sqlite3_column_bytes(stmt, 1);

        const void *cipher = sqlite3_column_blob(stmt, 2);
        int cipher_len = sqlite3_column_bytes(stmt, 2);

        if (!nonce || nonce_len != crypto_secretbox_NONCEBYTES ||
            !cipher || cipher_len <= 0 || (size_t)cipher_len > DB_MAX_CIPHER) {
            sqlite3_finalize(stmt);
            return -1;
        }

        memcpy(nonce_out, nonce, crypto_secretbox_NONCEBYTES);
        memcpy(ciphertext_out, cipher, (size_t)cipher_len);
        *cipher_len_out = (size_t)cipher_len;

        sqlite3_finalize(stmt);
        return 0;
    }

    sqlite3_finalize(stmt);
    return -1;
}

int db_list_entries(int user_id) {
    const char *sql = "SELECT id, url, username FROM vault_entries WHERE user_id = ? ORDER BY id ASC;";
    sqlite3_stmt *stmt = NULL;

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_int(stmt, 1, user_id);

    printf("\n%-5s | %-30s | %-20s\n", "ID", "URL", "Username");
    printf("--------------------------------------------------------------\n");

    int count = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        int id = sqlite3_column_int(stmt, 0);
        const char *url = (const char *)sqlite3_column_text(stmt, 1);
        const char *uname = (const char *)sqlite3_column_text(stmt, 2);
        printf("%-5d | %-30s | %-20s\n", id, url ? url : "", uname ? uname : "");
        count++;
    }
    if (count == 0) {
        printf("(No entries found)\n");
    }
    printf("\n");

    sqlite3_finalize(stmt);
    return 0;
}

int db_del_entry(int user_id, const char *url) {
    const char *sql = "DELETE FROM vault_entries WHERE user_id = ? AND url = ?;";
    sqlite3_stmt *stmt = NULL;

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) return -1;

    sqlite3_bind_int(stmt, 1, user_id);
    sqlite3_bind_text(stmt, 2, url, -1, SQLITE_STATIC);

    int rc = sqlite3_step(stmt);
    int changes = sqlite3_changes(db);
    sqlite3_finalize(stmt);

    return (rc == SQLITE_DONE && changes > 0) ? 0 : -1;
}