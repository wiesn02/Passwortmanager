#include "db.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

sqlite3* database = NULL;  // definition of db

// databaseBuffer pointer serialized database / NULL, databaseLength = Buffer Length
int InitDatabase(unsigned char* databaseBuffer, size_t databaseLength) {
    int statusCode = sqlite3_open(":memory:", &database);
    if (statusCode != SQLITE_OK) {
        fprintf(stderr, "Error: Failed to open DB in RAM: %s\n", sqlite3_errmsg(database));
        return statusCode;
    }

    if (databaseBuffer && databaseLength > 0) {
        statusCode = sqlite3_deserialize(database, "main", databaseBuffer, databaseLength, databaseLength, SQLITE_DESERIALIZE_FREEONCLOSE);
        if (statusCode != SQLITE_OK) {
            fprintf(stderr, "Error: Failed to deserialize DB: %s\n", sqlite3_errmsg(database));
            sqlite3_close(database);
            database = NULL;
            return statusCode;
        }
    }

    // Database Tables
    // OPTIONAL TODO: Replace with .sql scheme
    const char* sql_entries =
        "CREATE TABLE IF NOT EXISTS entries ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "title TEXT NOT NULL,"
        "username TEXT,"
        "password TEXT NOT NULL,"
        "url TEXT,"
        "notes TEXT"
        ");";

    // Execute SQL Query on database
    char* errorMessage = NULL;
    statusCode = sqlite3_exec(database, sql_entries, NULL, NULL, &errorMessage); // NULL callback           // FUER DOKU: Schutz vor SQL-Injection + warum unten prepared statements
    if (statusCode != SQLITE_OK) {                                                                          // https://sqlite.org/c3ref/exec.html
        fprintf(stderr, "Error: Couldnt create database tables: %s\n", errorMessage);
        sqlite3_free(errorMessage);
        sqlite3_close(database);
        database = NULL;
        return statusCode;
    }

    return SQLITE_OK;
}

// Serializes current database
unsigned char* serializeDatabase(size_t* OutputLength) {
    if (!database) {
        return NULL;
    } 

    sqlite3_int64 length = 0; // must be 64 Bit
    unsigned char* serializedDatabaseData = sqlite3_serialize(database, "main", &length, 0); // default sqlite scheme

    if (!serializedDatabaseData) {
        return NULL;
    }

    // return call
    *OutputLength = (size_t)length;
    return serializedDatabaseData;
}

// close current database handle + reset null pointer
void closeDatabase() {
    if (database) {
        sqlite3_close(database);
        database = NULL;
    }
}


// Insert SQL Query
int insertEntry(const char* title, const char* username, const char* password, const char* url, const char* notes) {
    const char* sqlInsertStatement =
        "INSERT INTO entries (title, username, password, url, notes) "
        "VALUES (?, ?, ?, ?, ?);";

    // prepared statement createss placeholders
    sqlite3_stmt* stmt;
    int statusCode = sqlite3_prepare_v2(database, sqlInsertStatement, -1, &stmt, NULL); // FUER DOKU: https://sqlite.org/c3ref/prepare.html
    if (statusCode != SQLITE_OK) {
        return statusCode;
    }

    // bind parameters to placeholder above
    sqlite3_bind_text(stmt, 1, title, -1, SQLITE_TRANSIENT);    // FUER DOKU: https://sqlite.org/c3ref/bind_blob.html
    sqlite3_bind_text(stmt, 2, username, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, password, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, url, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 5, notes, -1, SQLITE_TRANSIENT);

    // insert
    statusCode = sqlite3_step(stmt);
    if (statusCode != SQLITE_DONE) {
        return FAILURE_SQL;
    }

    statusCode = sqlite3_finalize(stmt);
    if (statusCode == SQLITE_OK) {
        return SUCCESS;
    }
    else {
        return FAILURE_SQL;
    }
}

// Select SQL Query
int getEntryById(int id, char* title, size_t titleLength, char* username, size_t usernameLength,
    char* password, size_t passwordLength,
    char* url, size_t urlLength,
    char* notes, size_t notesLength
) {
    const char* sqlSelectStatement =
        "SELECT title, username, password, url, notes FROM entries WHERE id = ?;";

    sqlite3_stmt* stmt;
    int statusCode = sqlite3_prepare_v2(database, sqlSelectStatement, -1, &stmt, NULL);
    if (statusCode != SQLITE_OK) {
        return statusCode;
    }

    sqlite3_bind_int(stmt, 1, id);

    statusCode = sqlite3_step(stmt);
    if (statusCode != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return statusCode;
    }

    const unsigned char* column;

    column = sqlite3_column_text(stmt, 0);
    if (column) {
        snprintf(title, titleLength, "%s", column);        // FUER DOKU: Eventuell auf unsichere Funktion eingehen
    }

    column = sqlite3_column_text(stmt, 1);
    if (column) {
        snprintf(username, usernameLength, "%s", column);
    }

    column = sqlite3_column_text(stmt, 2);
    if (column) {
        snprintf(password, passwordLength, "%s", column);
    }

    column = sqlite3_column_text(stmt, 3);
    if (column) {
        snprintf(url, urlLength, "%s", column);
    }

    column = sqlite3_column_text(stmt, 4);
    if (column) {
        snprintf(notes, notesLength, "%s", column);
    }

    statusCode = sqlite3_finalize(stmt);
    if (statusCode != SQLITE_OK) {
        return statusCode;
    }

    return SUCCESS;
}

// Update SQL Query
int updateEntry(int id, const char* title, const char* username, const char* password, const char* url, const char* notes) {
    const char* sqlUpdateStatement =
        "UPDATE entries SET title = ?, username = ?, password = ?, url = ?, notes = ? "
        "WHERE id = ?;";

    sqlite3_stmt* stmt;
    int statusCode = sqlite3_prepare_v2(database, sqlUpdateStatement, -1, &stmt, NULL);
    if (statusCode != SQLITE_OK) {
        return statusCode;
    }

    sqlite3_bind_text(stmt, 1, title, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, username, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, password, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, url, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 5, notes, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 6, id);

    statusCode = sqlite3_step(stmt);
    if (statusCode != SQLITE_DONE) {
        return FAILURE_SQL;
    }

    statusCode = sqlite3_finalize(stmt);
    if (statusCode == SQLITE_OK) {
        return SUCCESS;
    }
    else {
        return FAILURE_SQL;
    }
}

// Delete SQL Query
int deleteEntry(int id) {
    const char* sql = "DELETE FROM entries WHERE id = ?;";

    sqlite3_stmt* stmt;
    int statusCode = sqlite3_prepare_v2(database, sql, -1, &stmt, NULL);
    if (statusCode != SQLITE_OK) {
        return statusCode;
    }

    sqlite3_bind_int(stmt, 1, id);

    statusCode = sqlite3_step(stmt);
    if (statusCode != SQLITE_DONE) {
        return FAILURE_SQL;
    }

    statusCode = sqlite3_finalize(stmt);
    if (statusCode == SQLITE_OK) {
        return SUCCESS;
    }
    else {
        return FAILURE_SQL;
    }
}
