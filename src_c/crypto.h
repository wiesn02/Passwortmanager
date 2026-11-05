#ifndef CRYPTO_H
#define CRYPTO_H

#include "basicTypes.h"
#include <stddef.h>
#include <sodium.h>

                                                                                                                                     // FUER DOKU: Salts Iterationen und Rainbow Tables
#define SALT_SIZE crypto_pwhash_SALTBYTES   // Argon2ID saltsize
#define HEADER_SIZE crypto_secretstream_xchacha20poly1305_HEADERBYTES // Size of headers for XChaCha20-Poly1305 secretstream
#define KEYCHECK_PLAINTEXT "EncryptionWasSuccessfull" // check for correct key derivation / master password                          // FUER DOKU: Eventuell kurz auf Magicheader eingehen
#define KEYCHECK_LENGTH 64   // Max length encyrpted marker (ciphertext + auth)


typedef struct {
    unsigned char salt[SALT_SIZE];
    unsigned char keycheckCipher[KEYCHECK_LENGTH];  // encrypted marker to verify masterkey
    unsigned char keycheck_header[HEADER_SIZE]; // Secretsream header for marker
    unsigned long long keycheckLength; // Encrypted marker actual length    64bit libsodium specific: https://libsodium.gitbook.io/doc/internals
} metaStruct;


int setupMasterKey(
    const char* masterPassword,
    metaStruct* metadata,
    unsigned char* derivedKey
);

int verifyMasterkey(
    const char* masterPassword,
    const metaStruct* metadata,
    unsigned char* derivedKey
);

int decryptDatabaseToMemory(
    const char* encryptedPath,
    unsigned char** outBuffer,
    size_t* outLength,
    const unsigned char* encryptionKey
);

int encryptMemoryToDatabase(
    const unsigned char* buffer,
    size_t lengthPlain,
    const char* encryptedPath,
    const unsigned char* encryptionKey
);

#endif
