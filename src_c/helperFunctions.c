#include "helperFunctions.h"

#include <ctype.h>
#include <sodium.h>
#include <string.h>


#if defined(__linux__)				// For Linux-GCC
#include <termios.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

static int getch() {
	struct termios oldt, newt;
	int key;
	tcgetattr(STDIN_FILENO, &oldt);
	newt = oldt;
	newt.c_lflag &= ~(ICANON | ECHO);
	tcsetattr(STDIN_FILENO, TCSANOW, &newt);
	key = getchar();
	tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
	return key;
}

#elif defined(_WIN32)				// For Windows x64
#include <conio.h>
#include <io.h>
#include <sys/stat.h>
#include <direct.h>
#ifndef S_ISDIR
#define S_ISDIR(mode) (((mode) & _S_IFDIR) != 0)
#endif

#else
#error "Unsupported platform"

#endif

// Internal Function declarations

static sint32 check_classes(const char* buffer, size_t buffersize);
static sint32 check_repeated_characters(const char* buffer, size_t buffersize);
static sint32 check_sequences(const char* buffer, size_t buffersize);

static uint8 read_key(void);

static sint32 valid_input_username(uint8 key);
static sint32 valid_input_password(uint8 key);
static sint32 valid_input_line(uint8 key);

static sint32 read_input(
	char* buffer,
	size_t buffersize,
	size_t min_length,
	int (*is_valid_char)(unsigned char),
	uint8 mask_output);


/* +++++++++++++++++++++++++++++++++++++++++++++++++++++++ HELPER FUNCTIONS +++++++++++++++++++++++++++++++++++++++++++++++++++++++ */


/* +++++++++++++++++++++++++++++++++++++++++++++++++++++++ DIRECTORY CREATE +++++++++++++++++++++++++++++++++++++++++++++++++++++++ */


sint32 create_dir(const char* path) {
	struct stat st;

	// Check if directory exists
	if (stat(path, &st) == 0) {
		if (S_ISDIR(st.st_mode)) {
			return SUCCESS;  // already exists
		}
		else {
			return CUSTOM_ERROR_DIRECTORY;  // exists but not a directory
		}
	}

#ifdef _WIN32
	// On Windows, create directory
	if (_mkdir(path) != 0) {
		return CUSTOM_ERROR_DIRECTORY;
	}

#else
	// On Linux, create directory with 0777 permissions (all users can read/write/execute)
	if (mkdir(path, 0777) != 0) {
		return CUSTOM_ERROR_DIRECTORY;
	}
#endif

	return SUCCESS;
}


/* +++++++++++++++++++++++++++++++++++++++++++++++++++++++ SECURE FILE CREATE +++++++++++++++++++++++++++++++++++++++++++++++++++++++ */


FILE* secure_create_file(const char* path) {
#if defined(_WIN32)
	// Windows: _S_IREAD | _S_IWRITE for user, "wbx" = write, binary, exclusive
	FILE* f = fopen(path, "wbx");
	if (!f) return NULL;

	// set rights to user-only
	_chmod(path, _S_IREAD | _S_IWRITE);
	return f;

#else
	// Unix/Linux: open + fdopen for secure, exclusive, user-only file create
	int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR);
	if (fd == -1) return NULL;

	FILE* f = fdopen(fd, "wb");
	if (!f) {
		close(fd);
		return NULL;
	}

	return f;
#endif
}


/* +++++++++++++++++++++++++++++++++++++++++++++++++++++++ PASSWORD QUALITY CHECK +++++++++++++++++++++++++++++++++++++++++++++++++++++++ */


sint32 check_password_quality(const char *buffer, size_t buffersize)
{
	if (check_classes(buffer, buffersize) == FAILURE_QUALITYCHECK)
	{
		printf("\nPlease use at least one lowercase, one uppercase, one digit and one special character!\n");
		return FAILURE_QUALITYCHECK;
	}

	if (check_repeated_characters(buffer, buffersize) == FAILURE_QUALITYCHECK)
	{
		printf("\nPlease do not use the same character three times in a row!\n");
		return FAILURE_QUALITYCHECK;
	}

	if (check_sequences(buffer, buffersize) == FAILURE_QUALITYCHECK)
	{
		printf("\nPlease do not use sequences like abc or 123!\n");
		return FAILURE_QUALITYCHECK;
	}

	printf("\nPassword does meet security requirements and is strong!\n");
	return SUCCESS;
}

static sint32 check_classes(const char *buffer, size_t buffersize)
{
	uint8 lowercase = 0;
	uint8 uppercase = 0;
	uint8 digit = 0;
	uint8 special = 0;

	for (size_t i = 0; i < buffersize - 1 && buffer[i] != '\0'; i++) 
	{
		if (islower(buffer[i]))
		{
			lowercase = 1;
		}
		else if (isupper(buffer[i]))
		{
			uppercase = 1;
		}
		else if (isdigit(buffer[i]))
		{
			digit = 1;
		}
		else
		{
			special = 1;
		}
	}
	
	uint8 sum;
	sum = lowercase + uppercase + digit + special;

	if (sum >= 4)
	{
		return SUCCESS;
	}
	else
	{
		return FAILURE_QUALITYCHECK;
	}
}

static sint32 check_repeated_characters(const char *buffer, size_t buffersize)
{
	uint8 count = 1;

	for (size_t i = 1; i < buffersize && buffer[i] != '\0'; i++)
	{
		if (buffer[i] == buffer[i - 1])
		{
			count++;
			if (count > 2)
			{
				return FAILURE_QUALITYCHECK;
			}
		}
		else
		{
			count = 1;
		}
	}
	return SUCCESS;
}

static sint32 check_sequences(const char *buffer, size_t buffersize)
{
	for (size_t i = 2; i < buffersize && buffer[i] != '\0'; i++)
	{
		if (buffer[i] == buffer[i - 1] + 1 && buffer[i - 1] == buffer[i - 2] + 1)
		{
			return FAILURE_QUALITYCHECK;
		}
	}
	return SUCCESS;
}


/* +++++++++++++++++++++++++++++++++++++++++++++++++++++++ INPUT MANAGEMENT +++++++++++++++++++++++++++++++++++++++++++++++++++++++ */


static uint8 read_key(void)
{
	#if defined(_WIN32)
		sint32 key = _getch();

		// ignore special keys
		if (key == 0 || key == 224)
		{
			_getch(); // read second byte
			return IGNORE_KEY;
		}
		return (uint8)key;

	#elif defined(__linux__)
		sint32 key = getch();
		if (key < 0 || key > 255) 
		{
			return IGNORE_KEY;
		}
		return (uint8)key;

	#else
		return IGNORE_KEY;

	#endif
}

static sint32 valid_input_username(uint8 key)
{
	// allow A-Z, a-z, 0-9 and following characters: - _
	const char *allowed =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"abcdefghijklmnopqrstuvwxyz"
		"0123456789"
		"-_";

	return strchr(allowed,(char)key) != NULL;
}

static sint32 valid_input_password(uint8 key)
{
	// allow all ASCII characters (ASCII 33 - 126)
	const char *allowed =
		"!\"#$%&'()*+,-./"
		"0123456789"
		":;<=>?@" 
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ" 
		"[\\]^_"
		"abcdefghijklmnopqrstuvwxyz"
		"{|}~";

	return strchr(allowed,(char)key) != NULL;
}

static sint32 valid_input_line(uint8 key)
{
	// allow all ASCII characters including space (ASCII 32 - 126)
	const char *allowed =
		" "
		"!\"#$%&'()*+,-./"
		"0123456789"
		":;<=>?@"
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"[\\]^_"
		"abcdefghijklmnopqrstuvwxyz"
		"{|}~";

	return strchr(allowed, (char)key) != NULL;
}

static sint32 read_input(
	char *buffer,
	size_t buffersize,
	size_t min_length,
	sint32 (*is_valid_char)(unsigned char),
	uint8 mask_output    // 0 = normal, 1 = '*'
)
{
	// check if buffersize is big enough
	if (!buffer || buffersize < 2)
	{
		if (buffer)
		{
			buffer[0] = '\0';
		}
		printf("\nbuffer too small\n");
		return FAILURE_INPUT_READ;
	}

	buffer[0] = '\0';
	uint32 i = 0;
	uint8 key;

	while (1)
	{
		key = read_key();
		if (key == IGNORE_KEY)
		{ 
			continue;
		}

		// ENTER
		if (key == '\r' || key == '\n')
		{
			buffer[i] = '\0';
			printf("\n");

			if (i < min_length)
			{
				sodium_memzero(buffer, buffersize);
				printf("\ninput too short, min %zu characters required\n", min_length);
				return FAILURE_INPUT_READ;
			}
			return SUCCESS;
		}

		// ESC
		if (key == 27)
		{
			sodium_memzero(buffer, buffersize);
			printf("\n\ncancelled\n");
			return FAILURE_INPUT_READ;
		}

		// BACKSPACE
		if (key == '\b' || key == 127)
		{
			if (i > 0)
			{
				buffer[--i] = '\0';
				printf("\b \b");
				fflush(stdout);
			}
			continue;
		}

		// valid char check
		if (is_valid_char && is_valid_char((unsigned char)key))
		{
			if (i < buffersize - 1)
			{
				buffer[i++] = (char)key;
				printf("%c", mask_output ? '*' : key);
				fflush(stdout);
			}
			// ignore input if max size is already reached
		}
		// ignore every other input silent
	}
}

sint32 read_username(char *buffer, size_t buffersize)
{
	return read_input(
		buffer,
		buffersize,
		USERNAME_LENGTH_MIN,
		valid_input_username,
		0   // print input normal
	);
}

sint32 read_password(char *buffer, size_t buffersize, uint8 u8_minCharRequired)
{
	return read_input(
		buffer,
		buffersize,
		u8_minCharRequired,
		valid_input_password,
		1   // print * instead of input
	);
}

sint32 read_line(char *buffer, size_t buffersize, uint8 u8_minCharRequired)
{
	return read_input(
		buffer,
		buffersize,
		u8_minCharRequired,
		valid_input_line,
		0   // print input normal
	);
}

uint8 get_menu_choice(void) 
{
	sint32 s32_input = getchar();

	if (s32_input == EOF)
	{
		return 0; // treat EOF as "quit"
	}

	// flush rest of line
	sint32 s32_rest;
	while ((s32_rest = getchar()) != '\n' && s32_rest != EOF)
	{
		;
	}

	// validate input
	if (isdigit(s32_input) == FALSE)
	{
		return 255; // invalid
	}

	return (uint8)(s32_input - '0');
}
