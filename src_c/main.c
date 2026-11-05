#include "main.h"
#include "userSession.h"
#include "helperFunctions.h"
#include "db.h"
#include "crypto.h"
#include "sqlite3.h"

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <sodium.h>
#include <stdlib.h>
#include <time.h>

#if defined(_WIN32)
#include <windows.h>
#include <io.h>
#include <fcntl.h>
#else
#include <unistd.h>
#include <fcntl.h>
#endif


static sint32 save_meta(const char* path, const metaStruct* meta);
static sint32 load_meta(const char* path, metaStruct* meta);


sint32 main(void) {

	if (sodium_init() < 0)
	{
		return CUSTOM_ERROR; // initialization of sodium failed
	}

	if (create_dir("vault") != 0) {
		printf("folder 'vault' could not be created\n");
		return CUSTOM_ERROR; // failed to create folder vault
	}

	uint8 u8_menu_choice;
	char c_username[USERNAME_LENGTH_MAX];
	char c_password[PASSWORD_LENGTH_MAX];
	char c_pathDb[PATH_LENGTH_MAX];
	char c_pathMeta[PATH_LENGTH_MAX];

	unsigned char c_masterKey[crypto_secretstream_xchacha20poly1305_KEYBYTES];
	metaStruct t_meta = {0};	//zero initialize everything

	FILE* f_db;
	FILE* f_meta;

	sint32 s32_setupKeyStatus;
	sint32 s32_verificationStatus;
	sint32 s32_dbStatusCode;
	sint32 s32_cryptoStatus;
	sint32 s32_metaDataStatus;
	sint32 s32_readInputStatus;
	sint32 s32_qualityCheckStatus;
	uint8 u8_registerReqFulfilled = FALSE;

	printf("\n******************* PASSWORDMANAGER *******************\n");

	while (TRUE)
	{
		printf("\n\n------ Start MENU ------\n\n");
		printf("1: register\n");
		printf("2: login\n");
		printf("0: quit\n\n");


		u8_menu_choice = get_menu_choice();

		switch (u8_menu_choice) {

		case 0:	/* quit */

			sodium_memzero(c_username, sizeof(c_username));
			sodium_memzero(c_password, sizeof(c_password));
			sodium_memzero(c_masterKey, sizeof(c_masterKey));

			printf("goodbye\n");

			return 0;

		case 1: /* register */

			u8_registerReqFulfilled = FALSE;

			printf("enter new username (%d-%zu characters; only \"a-z A-Z 0-9 and - _\" are allowed; cancel with \"ESC\"):\n", USERNAME_LENGTH_MIN, (sizeof(c_username) - 1));
			s32_readInputStatus = read_username(c_username, sizeof(c_username));
			if (s32_readInputStatus != SUCCESS)
			{
				break;
			}

			// build the path strings
			snprintf(c_pathDb, sizeof(c_pathDb), "vault" PATH_SEP "%s.db", c_username);
			snprintf(c_pathMeta, sizeof(c_pathMeta), "vault" PATH_SEP "%s.meta", c_username);

			f_db = fopen(c_pathDb, "rb");
			if (f_db != NULL)			// file found means user already exists
			{
				fclose(f_db);
				f_db = NULL;
				printf("user already exists\n");
			}
			else
			{
				printf("enter new password (%d-%zu characters; all ASCII characters are allowed; cancel with \"ESC\"):\n", PASSWORD_LENGTH_MIN, (sizeof(c_password) - 1));
				s32_readInputStatus = read_password(c_password, sizeof(c_password), PASSWORD_LENGTH_MIN);
				if (s32_readInputStatus != SUCCESS)
				{
					break;
				}

				s32_qualityCheckStatus = check_password_quality(c_password, sizeof(c_password));
				if (s32_qualityCheckStatus != SUCCESS)
				{
					break;
				}

				char c_password_confirm[256];
				printf("confirm password:\n");
				s32_readInputStatus = read_password(c_password_confirm, sizeof(c_password_confirm), PASSWORD_LENGTH_MIN);
				if (s32_readInputStatus != SUCCESS)
				{
					break;
				}

				if (strlen(c_password) == strlen(c_password_confirm) && sodium_memcmp(c_password, c_password_confirm, strlen(c_password)) == 0)
				{
					u8_registerReqFulfilled = TRUE;
				}
				else
				{
					printf("passwords dont match\n");
				}

				sodium_memzero(c_password_confirm, sizeof(c_password_confirm));
			}

			if (u8_registerReqFulfilled == TRUE)
			{
				s32_setupKeyStatus = setupMasterKey(c_password, &t_meta, c_masterKey);

				// Open in write exclusive mode to create new user-only user files, then close them again to allow renaming in atomic file write actions
				f_db = secure_create_file(c_pathDb);
				f_meta = secure_create_file(c_pathMeta);
				if (f_db == NULL || f_meta == NULL)
				{
					return CUSTOM_ERROR_FILE_OPEN;
				}
				fclose(f_db);
				f_db = NULL;
				fclose(f_meta);
				f_meta = NULL;

				if (s32_setupKeyStatus == SUCCESS)
				{		
					size_t dbLen;
					unsigned char* dbBuffer = NULL;

					s32_dbStatusCode = InitDatabase(NULL, 0);
					if (s32_dbStatusCode == SQLITE_OK)
					{
						dbBuffer = serializeDatabase(&dbLen);
						s32_cryptoStatus = encryptMemoryToDatabase(dbBuffer, dbLen, c_pathDb, c_masterKey);
						s32_metaDataStatus = save_meta(c_pathMeta, &t_meta);

						if (s32_cryptoStatus == SUCCESS && s32_metaDataStatus == SUCCESS)
						{
							printf("register successfull\n");
						}
						else
						{
							printf("register failed\n");
						}
						closeDatabase();
					
						sodium_memzero(dbBuffer, dbLen);
						sqlite3_free(dbBuffer);
						dbBuffer = NULL;
					}
				}
				else
				{
					printf("register failed\n");
				}
			}

			break;

		case 2: /* login */

			printf("enter username:\n");
			s32_readInputStatus = read_line(c_username, sizeof(c_username), LINE_LENGTH_ZERO);
			if (s32_readInputStatus != SUCCESS)
			{
				break;
			}

			// build the path strings
			snprintf(c_pathDb, sizeof(c_pathDb), "vault" PATH_SEP "%s.db", c_username);
			snprintf(c_pathMeta, sizeof(c_pathMeta), "vault" PATH_SEP "%s.meta", c_username);

			f_db = fopen(c_pathDb, "rb");
			if (f_db != NULL)			// file found means user already exists
			{
				fclose(f_db);
				f_db = NULL;
				printf("enter password:\n");
				s32_readInputStatus = read_password(c_password, sizeof(c_password), LINE_LENGTH_ZERO);
				if (s32_readInputStatus != SUCCESS)
				{
					break;
				}

				s32_metaDataStatus = load_meta(c_pathMeta, &t_meta);
				s32_verificationStatus = verifyMasterkey(c_password, &t_meta, c_masterKey);

				if (s32_metaDataStatus == SUCCESS && s32_verificationStatus == SUCCESS) // means verification passed
				{
					printf("login successfull\n");
					size_t decryptedLen;
					unsigned char* decryptedDb = NULL;
					s32_cryptoStatus = decryptDatabaseToMemory(c_pathDb, &decryptedDb, &decryptedLen, c_masterKey);

					s32_dbStatusCode = InitDatabase(decryptedDb, decryptedLen);
					if (s32_dbStatusCode == SQLITE_OK && s32_cryptoStatus == SUCCESS)
					{
						user_session(c_username);

						decryptedDb = serializeDatabase(&decryptedLen);
						s32_cryptoStatus = encryptMemoryToDatabase(decryptedDb, decryptedLen, c_pathDb, c_masterKey);
						s32_metaDataStatus = save_meta(c_pathMeta, &t_meta);

						if (s32_cryptoStatus == SUCCESS && s32_metaDataStatus == SUCCESS)
						{
							printf("logged out\n\n");
						}
						else
						{
							printf("error while logging out, please check last session\n\n");
						}
						closeDatabase();
					}

					sodium_memzero(decryptedDb, decryptedLen);
					sqlite3_free(decryptedDb);
					decryptedDb = NULL;
				}
				else if (s32_verificationStatus == VERIFIFICATION_FAILED || s32_verificationStatus == CUSTOM_ERROR_SECRETSTREAM) // Usually a wrong password makes the stream fail already
				{
					printf("wrong password\n");
				}
				else
				{
					printf("login failed\n");
				}
			}
			else
			{
				printf("user not found\n");
			}

			break;

		default:

			printf("invalid choice\n");
			
			break;
		}

		sodium_memzero(c_username, sizeof(c_username));
		sodium_memzero(c_password, sizeof(c_password));
		sodium_memzero(c_masterKey, sizeof(c_masterKey));
	}

	return 0;
}







/* +++++++++++++++++++++++++++++++++++++++++++++++++++++++ META DATA MANAGEMENT +++++++++++++++++++++++++++++++++++++++++++++++++++++++ */

static sint32 save_meta(const char* path, const metaStruct* meta) {
	char tempPath[FILENAME_MAX];

	// Use timestamp + random value for uniqueness of filename, open in exclusive mode
	unsigned int randVal = randombytes_random();
	snprintf(tempPath, sizeof(tempPath), "%s.tmp.%lu.%u", path, (unsigned long)time(NULL), randVal);

	FILE* f = secure_create_file(tempPath);	// Open in exclusive mode, user-only
	if (f == NULL) {
		return CUSTOM_ERROR_FILE_OPEN;
	}

	if (fwrite(meta, sizeof(metaStruct), 1, f) != 1) {
		fclose(f);
		f = NULL;
		remove(tempPath);
		return CUSTOM_ERROR_FILE_WRITE;
	}

	// Flush and sync to disk for durability
	fflush(f);
#if defined(_WIN32)
	_commit(_fileno(f));
#else
	fsync(fileno(f));
#endif

	fclose(f);
	f = NULL;

	// Atomic rename
#if defined(_WIN32)
	if (MoveFileExA(tempPath, path, MOVEFILE_REPLACE_EXISTING) == 0) {
		remove(tempPath);
		return CUSTOM_ERROR_FILE_RENAME;
	}
#else
	if (rename(tempPath, path) != 0) {
		remove(tempPath);
		return CUSTOM_ERROR_FILE_RENAME;
	}
#endif

	return SUCCESS;
}

static sint32 load_meta(const char* path, metaStruct* meta) {
	FILE* f = fopen(path, "rb");
	if (f == NULL) {
		return CUSTOM_ERROR_FILE_OPEN;
	}

	if (fread(meta, sizeof(metaStruct), 1, f) != 1) {
		fclose(f);
		f = NULL;
		return CUSTOM_ERROR_FILE_READ;
	}

	fclose(f);
	f = NULL;
	return SUCCESS;
}
