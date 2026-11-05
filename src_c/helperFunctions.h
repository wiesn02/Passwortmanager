#ifndef HELPERFUNCTIONS_H
#define HELPERFUNCTIONS_H

#include "basicTypes.h"
#include <stdio.h>
#include <stddef.h>


sint32 create_dir(const char* path);

FILE* secure_create_file(const char* path);

sint32 check_password_quality(const char *buffer, size_t buffersize);

sint32 read_username(char *buffer, size_t buffersize);
sint32 read_password(char *buffer, size_t buffersize, uint8 u8_minCharRequired);
sint32 read_line(char *buffer, size_t buffersize, uint8 u8_minCharRequired);

uint8 get_menu_choice(void);

#endif
