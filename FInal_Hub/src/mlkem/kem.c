#include "indcpa.h"
#include "kem.h"
#include "params.h"
#include "randombytes.h"
#include "symmetric.h"
#include "verify.h"

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>


/*
 * ============================================================
 * DEBUG STORAGE
 * ============================================================
 */

static uint8_t debug_encap_message[KYBER_SYMBYTES];

static uint8_t debug_decap_message[KYBER_SYMBYTES];

static int debug_verify_fail = -1;


/*
 * ============================================================
 * DEBUG GETTERS
 * ============================================================
 */

bool mlkemDebugGetEncapMessage(
    uint8_t *out,
    size_t length
) {
    if (out == NULL) {
        return false;
    }

    if (length < KYBER_SYMBYTES) {
        return false;
    }

    memcpy(
        out,
        debug_encap_message,
        KYBER_SYMBYTES
    );

    return true;
}


bool mlkemDebugGetDecapMessage(
    uint8_t *out,
    size_t length
) {
    if (out == NULL) {
        return false;
    }

    if (length < KYBER_SYMBYTES) {
        return false;
    }

    memcpy(
        out,
        debug_decap_message,
        KYBER_SYMBYTES
    );

    return true;
}


int mlkemDebugGetVerifyFail(void)
{
    return debug_verify_fail;
}


/*
 * ============================================================
 * KEYPAIR DERANDOMIZED
 * ============================================================
 */

int PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair_derand(
    uint8_t *pk,
    uint8_t *sk,
    const uint8_t *coins
) {
    PQCLEAN_MLKEM512_CLEAN_indcpa_keypair_derand(
        pk,
        sk,
        coins
    );


    /*
     * Store public key inside secret key.
     */
    memcpy(
        sk + KYBER_INDCPA_SECRETKEYBYTES,
        pk,
        KYBER_PUBLICKEYBYTES
    );


    /*
     * Store H(pk).
     */
    hash_h(
        sk + KYBER_SECRETKEYBYTES - 2 * KYBER_SYMBYTES,
        pk,
        KYBER_PUBLICKEYBYTES
    );


    /*
     * Store rejection secret z.
     */
    memcpy(
        sk + KYBER_SECRETKEYBYTES - KYBER_SYMBYTES,
        coins + KYBER_SYMBYTES,
        KYBER_SYMBYTES
    );


    return 0;
}


/*
 * ============================================================
 * KEYPAIR
 * ============================================================
 */

int PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair(
    uint8_t *pk,
    uint8_t *sk
) {
    uint8_t coins[2 * KYBER_SYMBYTES];


    randombytes(
        coins,
        2 * KYBER_SYMBYTES
    );


    PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair_derand(
        pk,
        sk,
        coins
    );


    return 0;
}


/*
 * ============================================================
 * ENCAPSULATION DERANDOMIZED
 * ============================================================
 */

int PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc_derand(
    uint8_t *ct,
    uint8_t *ss,
    const uint8_t *pk,
    const uint8_t *coins
) {
    uint8_t buf[2 * KYBER_SYMBYTES];

    uint8_t kr[2 * KYBER_SYMBYTES];


    /*
     * Copy random message.
     */
    memcpy(
        buf,
        coins,
        KYBER_SYMBYTES
    );


    /*
     * Save message for diagnostic output.
     */
    memcpy(
        debug_encap_message,
        buf,
        KYBER_SYMBYTES
    );


    /*
     * Compute H(pk).
     */
    hash_h(
        buf + KYBER_SYMBYTES,
        pk,
        KYBER_PUBLICKEYBYTES
    );


    /*
     * Derive:
     *
     * kr[0..31]  = shared secret
     * kr[32..63] = encryption coins
     */
    hash_g(
        kr,
        buf,
        2 * KYBER_SYMBYTES
    );


    /*
     * IND-CPA encryption.
     */
    PQCLEAN_MLKEM512_CLEAN_indcpa_enc(
        ct,
        buf,
        pk,
        kr + KYBER_SYMBYTES
    );


    /*
     * Output shared secret.
     */
    memcpy(
        ss,
        kr,
        KYBER_SYMBYTES
    );


    return 0;
}


/*
 * ============================================================
 * ENCAPSULATION
 * ============================================================
 */

int PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc(
    uint8_t *ct,
    uint8_t *ss,
    const uint8_t *pk
) {
    uint8_t coins[KYBER_SYMBYTES];


    randombytes(
        coins,
        KYBER_SYMBYTES
    );


    PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc_derand(
        ct,
        ss,
        pk,
        coins
    );


    return 0;
}


/*
 * ============================================================
 * DECAPSULATION
 * ============================================================
 */

int PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec(
    uint8_t *ss,
    const uint8_t *ct,
    const uint8_t *sk
) {
    int fail;


    /*
     * buf:
     *
     * buf[0..31]  = recovered message
     * buf[32..63] = H(pk)
     */
    uint8_t buf[2 * KYBER_SYMBYTES];


    /*
     * kr:
     *
     * kr[0..31]  = candidate shared secret
     * kr[32..63] = re-encryption coins
     */
    uint8_t kr[2 * KYBER_SYMBYTES];


    /*
     * Re-encrypted ciphertext.
     */
    uint8_t cmp[KYBER_CIPHERTEXTBYTES];


    /*
     * Public key stored inside secret key.
     */
    const uint8_t *pk =
        sk + KYBER_INDCPA_SECRETKEYBYTES;


    /*
     * ========================================================
     * STEP 1: DECRYPT
     * ========================================================
     */

    PQCLEAN_MLKEM512_CLEAN_indcpa_dec(
        buf,
        ct,
        sk
    );


    /*
     * Save recovered message.
     */
    memcpy(
        debug_decap_message,
        buf,
        KYBER_SYMBYTES
    );


    /*
     * ========================================================
     * STEP 2: APPEND H(pk)
     * ========================================================
     */

    memcpy(
        buf + KYBER_SYMBYTES,
        sk + KYBER_SECRETKEYBYTES - 2 * KYBER_SYMBYTES,
        KYBER_SYMBYTES
    );


    /*
     * ========================================================
     * STEP 3: DERIVE SHARED SECRET + COINS
     * ========================================================
     */

    hash_g(
        kr,
        buf,
        2 * KYBER_SYMBYTES
    );


    /*
     * ========================================================
     * STEP 4: RE-ENCRYPT
     * ========================================================
     */

    PQCLEAN_MLKEM512_CLEAN_indcpa_enc(
        cmp,
        buf,
        pk,
        kr + KYBER_SYMBYTES
    );


    /*
     * ========================================================
     * STEP 5: VERIFY CIPHERTEXT
     * ========================================================
     */

    fail =
        PQCLEAN_MLKEM512_CLEAN_verify(
            ct,
            cmp,
            KYBER_CIPHERTEXTBYTES
        );


    debug_verify_fail = fail;


    printf(
        "[ML-KEM] VERIFY FAIL = %d\n",
        fail
    );


    /*
     * ========================================================
     * STEP 6: REJECTION KEY
     * ========================================================
     */

    rkprf(
        ss,
        sk + KYBER_SECRETKEYBYTES - KYBER_SYMBYTES,
        ct
    );


    /*
     * ========================================================
     * STEP 7: CONDITIONAL MOVE
     *
     * fail = 0:
     *     ss = kr
     *
     * fail = 1:
     *     ss = rejection key
     * ========================================================
     */

    PQCLEAN_MLKEM512_CLEAN_cmov(
        ss,
        kr,
        KYBER_SYMBYTES,
        (uint8_t)(1 - fail)
    );


    return 0;
}