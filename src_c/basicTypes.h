#ifndef BASICTYPES_H
#define BASICTYPES_H

#include <stdint.h>


/* Unsigned integer types */
typedef uint8_t  uint8;
typedef uint16_t uint16;
typedef uint32_t uint32;
typedef uint64_t uint64;

/* Signed integer types */
typedef int8_t   sint8;
typedef int16_t  sint16;
typedef int32_t  sint32;
typedef int64_t  sint64;

/* Floating point types */
typedef float     float32;
typedef double    float64;

/* Constants */
#define TRUE					 1
#define FALSE					 0

#define SUCCESS					 0

#define ENTRY_FOUND				 0
#define NO_ENTRY_FOUND 			-100

#define VERIFIFICATION_FAILED 	-101

#define FAILURE_INPUT_READ		-102
#define FAILURE_QUALITYCHECK	-103
#define FAILURE_SQL				-104

#define IGNORE_KEY	 			 254

#define CUSTOM_ERROR						-1
#define CUSTOM_ERROR_FILE_OPEN				-2
#define CUSTOM_ERROR_FILE_READ				-3
#define CUSTOM_ERROR_FILE_WRITE				-4
#define CUSTOM_ERROR_FILE_RENAME			-5
#define CUSTOM_ERROR_SECRETSTREAM_INIT		-6
#define CUSTOM_ERROR_SECRETSTREAM			-7
#define CUSTOM_ERROR_MEMORY_ALLOC			-8
#define CUSTOM_ERROR_CRYPTO					-9
#define CUSTOM_ERROR_DIRECTORY				-10


#ifdef _WIN32
#define PATH_SEP "\\"
#else
#define PATH_SEP "/"
#endif

#define PATH_LENGTH_MAX 64

#define USERNAME_LENGTH_MIN 5 // min 5 to prevent usage of external windows device names
#define USERNAME_LENGTH_MAX 33 // actual max length is 1 less due to array end

#define PASSWORD_LENGTH_MIN 12 // poolsize is 94 characters, so the entropy with a length of 12 is ~79 Bit
#define PASSWORD_LENGTH_MAX 65 // actual max length is 1 less due to array end

#define LINE_LENGTH_ZERO 0
#define LINE_LENGTH_MIN  1
#define LINE_LENGTH_MAX  65 // for this project are 64 characters enough input length

#endif
