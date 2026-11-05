#include "crypto.h"
#include "sqlite3.h"
#include "helperFunctions.h"

#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if defined(_WIN32)
#include <windows.h>
#include <io.h>
#include <fcntl.h>
#else
#include <unistd.h>
#include <fcntl.h>
#endif


/* masterPassword: password entered by user
*  metadata: metadata for encryption (salt)
*  derivedKey: Key derived by masterPassword + Salt via Argon2ID
*/

int setupMasterKey(const char* masterPassword, metaStruct* metadata, unsigned char* derivedKey) {

    // Random salt generation saved in metadata
    randombytes_buf(metadata->salt, SALT_SIZE);

    // https://libsodium.gitbook.io/doc/password_hashing/default_phf
    // Derives a key with the master password and salt via Argon2ID
    if (crypto_pwhash(
        derivedKey,
        crypto_secretstream_xchacha20poly1305_KEYBYTES,
        masterPassword,
        strlen(masterPassword),
        metadata->salt,
        crypto_pwhash_OPSLIMIT_MODERATE,        // Limits to make brute force based attacks harder
        crypto_pwhash_MEMLIMIT_MODERATE,
        crypto_pwhash_ALG_ARGON2ID13) != 0)
    {
        return CUSTOM_ERROR_CRYPTO;
    }

    // state for the XChaCha20-Poly1305 secret stream
    crypto_secretstream_xchacha20poly1305_state secretStreamState;

    // Initialize the secret stream for encryption using the stream header and the derived key
    if (crypto_secretstream_xchacha20poly1305_init_push(
        &secretStreamState,
        metadata->keycheck_header,
        derivedKey) != 0)
    {
        return CUSTOM_ERROR_SECRETSTREAM_INIT;
    }

    // Encrypt the keycheck plaintext for verication of key
    if (crypto_secretstream_xchacha20poly1305_push(
        &secretStreamState,
        metadata->keycheckCipher,
        &metadata->keycheckLength,
        (const unsigned char*)KEYCHECK_PLAINTEXT,
        strlen(KEYCHECK_PLAINTEXT),
        NULL,
        0,
        crypto_secretstream_xchacha20poly1305_TAG_FINAL) != 0)
    {
        return CUSTOM_ERROR_SECRETSTREAM;
    }
 
    return SUCCESS;
}



int verifyMasterkey(const char* masterPassword, const metaStruct* metadata, unsigned char* derivedKey) {
    // Derives a key with the master password and salt via Argon2ID
    if (crypto_pwhash(
        derivedKey,
        crypto_secretstream_xchacha20poly1305_KEYBYTES,
        masterPassword,
        strlen(masterPassword),
        metadata->salt,
        crypto_pwhash_OPSLIMIT_MODERATE,
        crypto_pwhash_MEMLIMIT_MODERATE,
        crypto_pwhash_ALG_ARGON2ID13) != 0)
    {
        return CUSTOM_ERROR_CRYPTO;
    }
    // state for the XChaCha20-Poly1305 secret stream
    crypto_secretstream_xchacha20poly1305_state secretStreamState;

    // Initialize the secret stream for decryption using the stored stream header and the derived key
    if (crypto_secretstream_xchacha20poly1305_init_pull(
        &secretStreamState,
        metadata->keycheck_header,
        derivedKey) != 0)
    {
        return CUSTOM_ERROR_SECRETSTREAM_INIT;
    }

    unsigned char decrypted[64];    // Buffer for decrypted keycheck plaintext
    unsigned long long decrypted_len; // Actual length of decrypted data
    unsigned char blockTag; // Tag indicating block type

    // Decrypt the stored keycheck ciphertext
    if (crypto_secretstream_xchacha20poly1305_pull(
        &secretStreamState,
        decrypted,
        &decrypted_len,
        &blockTag,
        metadata->keycheckCipher,
        metadata->keycheckLength,
        NULL,
        0) != 0)
    {
        return CUSTOM_ERROR_SECRETSTREAM;
    }

    // Verify that the decrypted plaintext matches the expected known marker string = key correct
    if (decrypted_len != strlen(KEYCHECK_PLAINTEXT) ||
        sodium_memcmp(decrypted, KEYCHECK_PLAINTEXT, decrypted_len) != 0)
    {
        return VERIFIFICATION_FAILED;
    }

    return SUCCESS;
}

/*encryptedPath: encrypted database path
* outBuffer: Pointer to encrypted memory buffer
* outLength: length of decrypted data
* encryptionKey: key for symmetric encryption
*/
int decryptDatabaseToMemory(const char* encryptedPath, unsigned char** outBuffer, size_t* outLength, const unsigned char* encryptionKey) {
    FILE* in = fopen(encryptedPath, "rb");
    if (in == NULL)
    {
        return CUSTOM_ERROR_FILE_OPEN;
    }

    // read secretstream header from the top of the file
    unsigned char header[HEADER_SIZE];
    if (fread(header, 1, HEADER_SIZE, in) != HEADER_SIZE)
    {
        fclose(in);
        in = NULL;
        return CUSTOM_ERROR_FILE_READ;
    }

    // Internal state for secret stream decryption
    crypto_secretstream_xchacha20poly1305_state secretStreamState;

    // Initialize decryption stream using header and key
    if (crypto_secretstream_xchacha20poly1305_init_pull(&secretStreamState, header, encryptionKey) != 0)
    {
        fclose(in);
        in = NULL;
        return CUSTOM_ERROR_SECRETSTREAM_INIT;
    }

    size_t cap = 8192; // output buffer capacityy
    size_t size = 0; // decrypted data size (current)

    unsigned char* buffer = sqlite3_malloc((int)cap); // dynamically output buffer allocation
    if (buffer == NULL)
    { 
        fclose(in);
        in = NULL;
        return CUSTOM_ERROR_MEMORY_ALLOC;
    }

    // Buffer for encrypted input blocks with auth bytes
    unsigned char block[4096 + crypto_secretstream_xchacha20poly1305_ABYTES];

    // read block for block from the encrypted file
    while (1)
    {
        size_t r = fread(block, 1, sizeof(block), in);

        if (r == 0)
        {
            if (ferror(in) != 0) {  // check for disk error
                free(buffer);
                buffer = NULL;
                fclose(in);
                in = NULL;
                return CUSTOM_ERROR;
            }
            break; // EOF
        }

        unsigned char decrypted[4096];
        unsigned long long decryptedLength;
        unsigned char blockTag;

        if (crypto_secretstream_xchacha20poly1305_pull(
            &secretStreamState,
            decrypted,
            &decryptedLength,
            &blockTag,
            block,
            r,
            NULL,
            0) != 0)
        {
            free(buffer);
            buffer = NULL;
            fclose(in);
            in = NULL;
            return CUSTOM_ERROR_SECRETSTREAM;
        }

        // Explicit bounds check 
        if (decryptedLength > sizeof(decrypted)) {
            free(buffer);
            buffer = NULL;
            fclose(in);
            in = NULL;
            return CUSTOM_ERROR_SECRETSTREAM;
        }

        // Expansion for the output buffer if necessary
        if (size + decryptedLength > cap)
        {
            cap *= 2;
            unsigned char* tmp = sqlite3_realloc(buffer, (int)cap);
            if (tmp == NULL)
            {
                free(buffer);
                buffer = NULL;
                fclose(in);
                in = NULL;
                return CUSTOM_ERROR_MEMORY_ALLOC;
            }
            buffer = tmp;

        }

        // Append decrypted data to output buffer
        memcpy(buffer + size, decrypted, decryptedLength);
        size += decryptedLength;

        // Stop at last block
        if (blockTag == crypto_secretstream_xchacha20poly1305_TAG_FINAL)
        {
            break;
        }
    }

    fclose(in);
    in = NULL;

    *outBuffer = buffer;
    *outLength = size;

    return SUCCESS;
}


/* buffer: plaintext data in memory
* lengthPlain: length of plaintext data
* encryptedPath: Output path for the encrypted data
* encryptionKey: key for symmetric encryption
*/
int encryptMemoryToDatabase(const unsigned char* buffer, size_t lengthPlain, const char* encryptedPath, const unsigned char* encryptionKey) {

    // Create a temporary filename in the same directory
    char tempPath[FILENAME_MAX];

    // Use timestamp + random value for uniqueness of filename, open in exclusive mode user-only
    unsigned int randVal = randombytes_random();
    snprintf(tempPath, sizeof(tempPath), "%s.tmp.%lu.%u", encryptedPath, (unsigned long)time(NULL), randVal);

    FILE* out = secure_create_file(tempPath);
    if (out == NULL)
    {
        return CUSTOM_ERROR_FILE_OPEN;
    }

    // Internal state for secret stream encryption
    crypto_secretstream_xchacha20poly1305_state secretStreamState;

    // Stream header  must be stored for decryption
    unsigned char header[HEADER_SIZE];

    // Initialize encryption stream using header and key
    if (crypto_secretstream_xchacha20poly1305_init_push(&secretStreamState, header, encryptionKey) != 0)
    {
        fclose(out);
        out = NULL;
        remove(tempPath);
        return CUSTOM_ERROR_SECRETSTREAM_INIT;
    }

    // Write header to top of file
    if (fwrite(header, 1, HEADER_SIZE, out) != HEADER_SIZE)
    {
        fclose(out);
        out = NULL;
        remove(tempPath);
        return CUSTOM_ERROR_FILE_WRITE;
    }

    // Buffer for encrypted output blocks
    unsigned char block[4096 + crypto_secretstream_xchacha20poly1305_ABYTES];
    size_t offset = 0;

    while (offset < lengthPlain)
    {
        // Determine size of the next plaintext chunk
        size_t chunk = (lengthPlain - offset > 4096) ? 4096 : (lengthPlain - offset);
        unsigned long long out_len;

        if (crypto_secretstream_xchacha20poly1305_push(
            &secretStreamState,
            block,
            &out_len,
            buffer + offset,
            chunk,
            NULL,
            0,
            (offset + chunk == lengthPlain)
            ? crypto_secretstream_xchacha20poly1305_TAG_FINAL
            : 0) != 0)
        {
            fclose(out);
            out = NULL;
            remove(tempPath);
            return CUSTOM_ERROR_SECRETSTREAM;
        }

        // Write encrypted block to file
        if (fwrite(block, 1, out_len, out) != out_len)
        {
            fclose(out);
            out = NULL;
            remove(tempPath);
            return CUSTOM_ERROR_FILE_WRITE;
        }
        offset += chunk;
    }


    // Flush and sync to disk for durability
    fflush(out);
#if defined(_WIN32)
    _commit(_fileno(out));
#else
    fsync(fileno(out));
#endif


    fclose(out);
    out = NULL;


    // Atomic rename
#if defined(_WIN32)
    if (MoveFileExA(tempPath, encryptedPath, MOVEFILE_REPLACE_EXISTING) == 0)
    {
        remove(tempPath);
        return CUSTOM_ERROR_FILE_RENAME;
    }
#else
    if (rename(tempPath, encryptedPath) != 0)
    {
        remove(tempPath);
        return CUSTOM_ERROR_FILE_RENAME;
    }
#endif

    return SUCCESS;
}




