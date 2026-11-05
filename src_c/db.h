#ifndef DB_H
#define DB_H

#include "sqlite3.h"
#include "basicTypes.h"
#include <stddef.h>

extern sqlite3* database;  // declaration of db

int InitDatabase(unsigned char* databaseBuffer, size_t databaseLength);

unsigned char* serializeDatabase(size_t* OutputLength);

void closeDatabase();

int insertEntry(
    const char* title,
    const char* username,
    const char* password,
    const char* url,
    const char* notes
);

int getEntryById(
    int id,
    char* title, size_t titleLength,
    char* username, size_t usernameLength,
    char* password, size_t passwordLength,
    char* url, size_t urlLength,
    char* notes, size_t notesLength
);

int updateEntry(
    int id,
    const char* title,
    const char* username,
    const char* password,
    const char* url,
    const char* notes
);

int deleteEntry(int id);
#endif 
