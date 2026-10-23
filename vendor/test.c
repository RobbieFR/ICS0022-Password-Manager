#include <stdio.h>
#include <stdlib.h>
#include "sqlite3.h"

int main(void) {
    sqlite3 *db = NULL;
    char *err_msg = NULL;
    int rc;

    // 1. Open (or create) database file
    rc = sqlite3_open("test.db", &db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return 1;
    }

    // 2. Create a table using sqlite3_exec (best for simple DDL commands)
    const char *sql_create = 
        "CREATE TABLE IF NOT EXISTS users ("
        "   id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "   name TEXT NOT NULL,"
        "   score REAL NOT NULL"
        ");";

    rc = sqlite3_exec(db, sql_create, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", err_msg);
        sqlite3_free(err_msg);
        sqlite3_close(db);
        return 1;
    }

    // 3. Insert records using prepared statements (safe against SQL injection)
    const char *sql_insert = "INSERT INTO users (name, score) VALUES (?, ?);";
    sqlite3_stmt *stmt = NULL;

    rc = sqlite3_prepare_v2(db, sql_insert, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare insert statement: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return 1;
    }

    struct {
        const char *name;
        double score;
    } sample_users[] = {
        {"Alice", 95.5},
        {"Bob",   82.0},
        {"Carol", 88.75}
    };

    for (int i = 0; i < 3; i++) {
        // SQLite parameters are 1-indexed
        sqlite3_bind_text(stmt, 1, sample_users[i].name, -1, SQLITE_STATIC);
        sqlite3_bind_double(stmt, 2, sample_users[i].score);

        if (sqlite3_step(stmt) != SQLITE_DONE) {
            fprintf(stderr, "Insert execution failed: %s\n", sqlite3_errmsg(db));
        }

        // Reset the statement to reuse it in the next loop iteration
        sqlite3_reset(stmt);
        sqlite3_clear_bindings(stmt);
    }

    // Free the statement handle
    sqlite3_finalize(stmt);

    // 4. Query data and iterate through rows
    const char *sql_select = "SELECT id, name, score FROM users WHERE score >= ? ORDER BY score DESC;";
    rc = sqlite3_prepare_v2(db, sql_select, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare select query: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return 1;
    }

    // Filter users with score >= 85.0
    sqlite3_bind_double(stmt, 1, 85.0);

    printf("--- Users with score >= 85.0 ---\n");
    // sqlite3_step returns SQLITE_ROW each time a new row is fetched
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        // Result columns are 0-indexed
        int id = sqlite3_column_int(stmt, 0);
        const unsigned char *name = sqlite3_column_text(stmt, 1);
        double score = sqlite3_column_double(stmt, 2);

        printf("ID: %d | Name: %-6s | Score: %.2f\n", id, name, score);
    }

    if (rc != SQLITE_DONE) {
        fprintf(stderr, "Execution finished with error: %s\n", sqlite3_errmsg(db));
    }

    // 5. Clean up statement and connection
    sqlite3_finalize(stmt);
    sqlite3_close(db);

    return 0;
}