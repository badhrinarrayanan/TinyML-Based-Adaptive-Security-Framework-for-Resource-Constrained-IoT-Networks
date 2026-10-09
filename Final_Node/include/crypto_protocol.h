#ifndef CRYPTO_PROTOCOL_H
#define CRYPTO_PROTOCOL_H

#include <Arduino.h>
#include <stdint.h>
#include <stddef.h>

// ============================================================
// AES-GCM
// ============================================================

#define GCM_NONCE_SIZE 12
#define GCM_TAG_SIZE   16

// ============================================================
// SECURITY MODES
// ============================================================

#define SECURITY_AES128    1
#define SECURITY_AES256    2
#define SECURITY_MLKEM512  3

// ============================================================
// PACKET TYPES
// ============================================================

#define PACKET_DATA    0x01
#define PACKET_KEM_KEY 0x02
#define PACKET_KEM_CT  0x03
#define PACKET_POLICY  0x04

// ============================================================
// ML-KEM-512
//
// Values taken from your api.h
// ============================================================

#define MLKEM512_SECRETKEY_SIZE   1632
#define MLKEM512_PUBLICKEY_SIZE    800
#define MLKEM512_CIPHERTEXT_SIZE   768
#define MLKEM512_SHARED_SIZE        32

// ============================================================
// AES-GCM
// ============================================================

void generateNonce(
    uint8_t nonce[GCM_NONCE_SIZE]
);

bool aesGcmEncrypt(
    const uint8_t* key,
    size_t keyLength,

    const uint8_t* plaintext,
    size_t plaintextLength,

    uint8_t nonce[GCM_NONCE_SIZE],

    uint8_t* ciphertext,

    uint8_t tag[GCM_TAG_SIZE]
);

bool aesGcmDecrypt(
    const uint8_t* key,
    size_t keyLength,

    const uint8_t* nonce,

    const uint8_t* ciphertext,
    size_t ciphertextLength,

    const uint8_t tag[GCM_TAG_SIZE],

    uint8_t* plaintext
);

// ============================================================
// ML-KEM-512 WRAPPERS
// ============================================================

bool mlkem512Keypair(
    uint8_t* publicKey,
    uint8_t* secretKey
);

bool mlkem512Encapsulate(
    const uint8_t* publicKey,
    uint8_t* ciphertext,
    uint8_t* sharedSecret
);

bool mlkem512Decapsulate(
    const uint8_t* ciphertext,
    const uint8_t* secretKey,
    uint8_t* sharedSecret
);

#endif