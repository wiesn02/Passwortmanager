#ifndef USERSESSION_H
#define USERSESSION_H

#include "basicTypes.h"
#include "helperFunctions.h"

typedef struct {

    char c_title[LINE_LENGTH_MAX];
    char c_username[LINE_LENGTH_MAX];
    char c_password[LINE_LENGTH_MAX];
    char c_url[LINE_LENGTH_MAX];
    char c_notes[LINE_LENGTH_MAX];

}T_Entry;


void user_session(const char* c_username);

#endif