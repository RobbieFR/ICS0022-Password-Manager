#include <stdio.h>
#include <stdlib.h>
#include <sqlite3.h>

int init_database(sqlite3 **db) {
    int rc = sqlite3_open("database.db", db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(*db));
        return rc;
    }

    const char *sql_users = 
        "CREATE TABLE IF NOT EXISTS users ("
        "user_id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "username TEXT UNIQUE NOT NULL, "
        "master_password_hash TEXT NOT NULL, "
        "salt BLOB NOT NULL);";

    const char *sql_vault = 
        "CREATE TABLE IF NOT EXISTS vault_entries ("
        "entry_id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "user_id INTEGER, "
        "encrypted_url TEXT NOT NULL, "
        "encrypted_username TEXT NOT NULL, "
        "encrypted_password TEXT NOT NULL, "
        "iv BLOB NOT NULL, "
        "FOREIGN KEY(user_id) REFERENCES users(user_id));";

    char *err_msg = NULL;
    rc = sqlite3_exec(*db, sql_users, 0, 0, &err_msg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error creating users table: %s\n", err_msg);
        sqlite3_free(err_msg);
        return rc;
    }

    rc = sqlite3_exec(*db, sql_vault, 0, 0, &err_msg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error creating vault_entries table: %s\n", err_msg);
        sqlite3_free(err_msg);
        return rc;
    }

    return SQLITE_OK;
}