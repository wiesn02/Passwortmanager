#include "userSession.h"
#include "db.h"
#include "sqlite3.h"

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <sodium.h>

static sint32 printAllEntriesTitles(void);
static sint32 getEntryIdByTitle(sint32* pt_id, const char* title);
static void wait_for_enter(void);

void user_session(const char* c_username)
{

	uint8 u8_menu_choice;
	uint8 u8_isLoggedIn = TRUE;
	T_Entry t_Entry;

	sint32 s32_searchStatus;
	sint32 s32_insertStatus;
	sint32 s32_updateStatus;
	sint32 s32_deleteStatus;
	sint32 s32_id = 0;
	sint32 s32_readInputStatus;


	printf("logged in as %s", c_username);

	while (u8_isLoggedIn == TRUE)
	{
		printf("\n\n------ MAIN MENU ------\n\n");
		printf("1: list entries\n");
		printf("2: create new entry\n");
		printf("3: read entry\n");
		printf("4: update entry\n");
		printf("5: delete entry\n");
		printf("0: log out\n\n");

		u8_menu_choice = get_menu_choice();

		switch (u8_menu_choice)
		{

		case 0: /* log out */

			printf("\nlogging out\n");
			u8_isLoggedIn = FALSE;

			break;

		case 1: /* list */

			printf("all entries:\n\n");
			if (printAllEntriesTitles() != SUCCESS)
			{
				printf("unable to print entries\n");
			}
			wait_for_enter();
			break;

		case 2:	/* create */

			printf("creating new entry:\n\n");
			printf("enter title of new entry:\n");
			s32_readInputStatus = read_line(t_Entry.c_title, sizeof(t_Entry.c_title), LINE_LENGTH_MIN);
			if (s32_readInputStatus != SUCCESS)
			{
				wait_for_enter();
				break;
			}

			s32_searchStatus = getEntryIdByTitle(NULL, t_Entry.c_title);

			if (s32_searchStatus == NO_ENTRY_FOUND)	// means entry doesnt exist yet
			{
				printf("enter username for new entry:\n");
				s32_readInputStatus = read_line(t_Entry.c_username, sizeof(t_Entry.c_username), LINE_LENGTH_ZERO);
				if (s32_readInputStatus != SUCCESS)
				{
					wait_for_enter();
					break;
				}
				printf("enter password for new entry:\n");
				s32_readInputStatus = read_password(t_Entry.c_password, sizeof(t_Entry.c_password), LINE_LENGTH_MIN);
				if (s32_readInputStatus != SUCCESS)
				{
					wait_for_enter();
					break;
				}
				printf("enter url for new entry:\n");
				s32_readInputStatus = read_line(t_Entry.c_url, sizeof(t_Entry.c_url), LINE_LENGTH_ZERO);
				if (s32_readInputStatus != SUCCESS)
				{
					wait_for_enter();
					break;
				}
				printf("enter notes for new entry:\n");
				s32_readInputStatus = read_line(t_Entry.c_notes, sizeof(t_Entry.c_notes), LINE_LENGTH_ZERO);
				if (s32_readInputStatus != SUCCESS)
				{
					wait_for_enter();
					break;
				}

				s32_insertStatus = insertEntry(t_Entry.c_title, 
													  t_Entry.c_username, 
													  t_Entry.c_password, 
													  t_Entry.c_url, 
													  t_Entry.c_notes);
				if (s32_insertStatus == SUCCESS)
				{
					printf("added new entry: %s\n", t_Entry.c_title);
				}
				else
				{
					printf("adding new entry failed\n");
				}
			}
			else if (s32_searchStatus == ENTRY_FOUND)
			{
				printf("entry already exists\n");
			}
			else
			{
				printf("SQLite error: %d\n", s32_searchStatus);
			}

			wait_for_enter();
			break;

		case 3: /* read */

			printf("which entry to read?\n\n");
			s32_readInputStatus = read_line(t_Entry.c_title, sizeof(t_Entry.c_title), LINE_LENGTH_MIN);
			if (s32_readInputStatus != SUCCESS)
			{
				wait_for_enter();
				break;
			}
		
			s32_searchStatus = getEntryIdByTitle(&s32_id, t_Entry.c_title);

			if (s32_searchStatus == ENTRY_FOUND)	// entry id with given title found
			{
				s32_searchStatus = getEntryById(s32_id,
												t_Entry.c_title, sizeof(t_Entry.c_title),
												t_Entry.c_username, sizeof(t_Entry.c_username),
												t_Entry.c_password, sizeof(t_Entry.c_password),
												t_Entry.c_url, sizeof(t_Entry.c_url),
												t_Entry.c_notes, sizeof(t_Entry.c_notes));

				if (s32_searchStatus == ENTRY_FOUND) // entry with given id found
				{
					printf("entry found:\n");
					printf("entry title: %s\n", t_Entry.c_title);
					printf("username:    %s\n", t_Entry.c_username);
					printf("password:    %s\n", t_Entry.c_password);
					printf("url:         %s\n", t_Entry.c_url);
					printf("notes:       %s\n", t_Entry.c_notes);
				}
			}
			else
			{
				printf("no such entry\n");
			}

			wait_for_enter();
			break;

		case 4: /* update */

			printf("which entry to update?\n\n");
			s32_readInputStatus = read_line(t_Entry.c_title, sizeof(t_Entry.c_title), LINE_LENGTH_MIN);
			if (s32_readInputStatus != SUCCESS)
			{
				wait_for_enter();
				break;
			}

			s32_searchStatus = getEntryIdByTitle(&s32_id, t_Entry.c_title);

			if (s32_searchStatus == ENTRY_FOUND)	// entry id with given title found
			{
				s32_searchStatus = getEntryById(s32_id,
					t_Entry.c_title, sizeof(t_Entry.c_title),
					t_Entry.c_username, sizeof(t_Entry.c_username),
					t_Entry.c_password, sizeof(t_Entry.c_password),
					t_Entry.c_url, sizeof(t_Entry.c_url),
					t_Entry.c_notes, sizeof(t_Entry.c_notes));

				if (s32_searchStatus == ENTRY_FOUND)	// entry with given id found
				{
					printf("updating this entry:\n");			// printing entry for user to check the current contents
					printf("entry title: %s\n", t_Entry.c_title);
					printf("username:    %s\n", t_Entry.c_username);
					printf("password:    %s\n", t_Entry.c_password);
					printf("url:         %s\n", t_Entry.c_url);
					printf("notes:       %s\n", t_Entry.c_notes);


					printf("\nenter updated username:\n");		// asking for new contents
					s32_readInputStatus = read_line(t_Entry.c_username, sizeof(t_Entry.c_username), LINE_LENGTH_ZERO);
					if (s32_readInputStatus != SUCCESS)
					{
						wait_for_enter();
						break;
					}
					printf("enter updated password:\n");
					s32_readInputStatus = read_password(t_Entry.c_password, sizeof(t_Entry.c_password), LINE_LENGTH_MIN);
					if (s32_readInputStatus != SUCCESS)
					{
						wait_for_enter();
						break;
					}
					printf("enter updated url:\n");
					s32_readInputStatus = read_line(t_Entry.c_url, sizeof(t_Entry.c_url), LINE_LENGTH_ZERO);
					if (s32_readInputStatus != SUCCESS)
					{
						wait_for_enter();
						break;
					}
					printf("enter updated notes:\n");
					s32_readInputStatus = read_line(t_Entry.c_notes, sizeof(t_Entry.c_notes), LINE_LENGTH_ZERO);
					if (s32_readInputStatus != SUCCESS)
					{
						wait_for_enter();
						break;
					}

					s32_updateStatus = updateEntry(s32_id,
												   t_Entry.c_title,
												   t_Entry.c_username,
												   t_Entry.c_password,
											       t_Entry.c_url,
						                           t_Entry.c_notes);

					if (s32_updateStatus == SUCCESS)
					{
						printf("updated entry: %s\n", t_Entry.c_title);
					}
					else
					{
						printf("updating entry failed\n");
					}
				}
			}
			else
			{
				printf("no such entry\n");
			}

			wait_for_enter();
			break;

		case 5: /* delete */

			printf("which entry to delete?\n\n");
			s32_readInputStatus = read_line(t_Entry.c_title, sizeof(t_Entry.c_title), LINE_LENGTH_MIN);
			if (s32_readInputStatus != SUCCESS)
			{
				wait_for_enter();
				break;
			}

			s32_searchStatus = getEntryIdByTitle(&s32_id, t_Entry.c_title);

			if (s32_searchStatus == ENTRY_FOUND)	// entry id with given title found
			{
				s32_searchStatus = getEntryById(s32_id,
					t_Entry.c_title, sizeof(t_Entry.c_title),
					t_Entry.c_username, sizeof(t_Entry.c_username),
					t_Entry.c_password, sizeof(t_Entry.c_password),
					t_Entry.c_url, sizeof(t_Entry.c_url),
					t_Entry.c_notes, sizeof(t_Entry.c_notes));

				if (s32_searchStatus == ENTRY_FOUND)	// entry with given id found
				{
					printf("deleting this entry:\n");			// printing entry for user to check the current contents
					printf("entry title: %s\n", t_Entry.c_title);
					printf("username:    %s\n", t_Entry.c_username);
					printf("password:    %s\n", t_Entry.c_password);
					printf("url:         %s\n", t_Entry.c_url);
					printf("notes:       %s\n", t_Entry.c_notes);

					printf("\nconfirm deleting this entry? Y:1 / N:0\n");
					uint8 u8_confirmDelete = get_menu_choice();

					if (u8_confirmDelete == TRUE)
					{
						s32_deleteStatus = deleteEntry(s32_id);

						if (s32_deleteStatus == SUCCESS)
						{
							printf("deleted entry: %s\n", t_Entry.c_title);
						}
					}
					else
					{
						printf("deletion cancelled\n");
					}
				}
			}
			else
			{
				printf("no such entry\n");
			}

			wait_for_enter();
			break;

		case 255:

			printf("choice must be a valid digit\n");

			wait_for_enter();
			break;

		default:

			printf("invalid choice\n");

			wait_for_enter();
			break;
		}

		sodium_memzero(&t_Entry, sizeof(T_Entry));
	}
}


static void wait_for_enter(void) {
	printf("\npress Enter to continue...");
	fflush(stdout);  // Make sure the message prints immediately

	int c;
	// Read and discard characters until newline
	while ((c = getchar()) != '\n' && c != EOF) {
		// do nothing
	}
}


/* +++++++++++++++++++++++++++++++++++++++++++++++++++++++ ENTRY MANAGEMENT +++++++++++++++++++++++++++++++++++++++++++++++++++++++ */

static sint32 printAllEntriesTitles(void) {

	const char* sqlSelectStatement = "SELECT title FROM entries;";

	sqlite3_stmt* stmt;
	sint32 s32_statusCode = sqlite3_prepare_v2(database, sqlSelectStatement, -1, &stmt, NULL);
	if (s32_statusCode != SQLITE_OK) {
		return s32_statusCode;
	}

	while ((s32_statusCode = sqlite3_step(stmt)) == SQLITE_ROW) {
		const unsigned char* title = sqlite3_column_text(stmt, 0);
		if (title) {
			printf("%s		", title);
		}
	}

	if (s32_statusCode != SQLITE_DONE) {
		sqlite3_finalize(stmt);
		return s32_statusCode;
	}

	s32_statusCode = sqlite3_finalize(stmt);
	if (s32_statusCode == SQLITE_OK) {
		printf("\n");
		return SUCCESS;
	}
	else {
		return FAILURE_SQL;
	}
}



static sint32 getEntryIdByTitle(int* pt_id, const char* title) {	//checks entry existence and returns its id if pt provided

		const char* sqlSelectStatement = "SELECT id FROM entries WHERE title = ?;";

		sqlite3_stmt* stmt;
		sint32 s32_statusCode = sqlite3_prepare_v2(database, sqlSelectStatement, -1, &stmt, NULL);
		if (s32_statusCode != SQLITE_OK) {
			return s32_statusCode;
		}

		sqlite3_bind_text(stmt, 1, title, -1, SQLITE_TRANSIENT);

		s32_statusCode = sqlite3_step(stmt);
		if (s32_statusCode == SQLITE_ROW) {
			if (pt_id != NULL) {
				*pt_id = sqlite3_column_int(stmt, 0);
			}
			sqlite3_finalize(stmt);
			return ENTRY_FOUND;
		}
		else if (s32_statusCode == SQLITE_DONE) {
			sqlite3_finalize(stmt);
			return NO_ENTRY_FOUND;
		}
		else {
			sqlite3_finalize(stmt);
			return s32_statusCode;
		}
	}