#include "indcpa.h"
#include "kem.h"
#include "params.h"
#include "randombytes.h"
#include "symmetric.h"
#include "verify.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

/*
 * ============================================================
 * DEBUG BUFFERS
 * ============================================================
 *
 * These store:
 *
 *   debug_encap_message = message generated during encapsulation
 *   debug_decap_message = message recovered during decapsulation
 *
 * They are used ONLY for debugging the ML-KEM implementation.
 */

static uint8_t debug_encap_message[KYBER_SYMBYTES];
static uint8_t debug_decap_message[KYBER_SYMBYTES];

/*
 * Stores the result of the ciphertext verification:
 *
 *   0 = verification PASS
 *   1 = verification FAIL
 *
 * Initial value -1 means decapsulation has not been executed yet.
 */
static int debug_verify_fail = -1;


/*************************************************
* Name:        PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair_derand
*
* Description: Generates public and private key
**************************************************/
int PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair_derand(
    uint8_t *pk,
    uint8_t *sk,
    const uint8_t *coins
) {
    /*
     * Generate the IND-CPA public and secret key.
     */
    PQCLEAN_MLKEM512_CLEAN_indcpa_keypair_derand(
        pk,
        sk,
        coins
    );

    /*
     * Store a copy of the public key inside the
     * ML-KEM secret key.
     *
     * ML-KEM-512:
     *
     *   IND-CPA secret key = 768 bytes
     *   Public key         = 800 bytes
     *
     * Therefore:
     *
     *   sk[768 ... 1567] = pk[0 ... 799]
     */
    memcpy(
        sk + KYBER_INDCPA_SECRETKEYBYTES,
        pk,
        KYBER_PUBLICKEYBYTES
    );

    /*
     * Store H(pk) inside the secret key.
     */
    hash_h(
        sk + KYBER_SECRETKEYBYTES - 2 * KYBER_SYMBYTES,
        pk,
        KYBER_PUBLICKEYBYTES
    );

    /*
     * Store z for implicit rejection.
     */
    memcpy(
        sk + KYBER_SECRETKEYBYTES - KYBER_SYMBYTES,
        coins + KYBER_SYMBYTES,
        KYBER_SYMBYTES
    );

    return 0;
}


/*************************************************
* Name:        PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair
**************************************************/
int PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair(
    uint8_t *pk,
    uint8_t *sk
) {
    uint8_t coins[2 * KYBER_SYMBYTES];

    /*
     * Generate random keypair coins.
     */
    randombytes(
        coins,
        2 * KYBER_SYMBYTES
    );

    /*
     * Generate deterministic keypair from coins.
     */
    PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair_derand(
        pk,
        sk,
        coins
    );

    return 0;
}


/*************************************************
* Name:        PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc_derand
*
* Description:
*   Deterministic ML-KEM encapsulation.
**************************************************/
int PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc_derand(
    uint8_t *ct,
    uint8_t *ss,
    const uint8_t *pk,
    const uint8_t *coins
) {
    /*
     * buf:
     *
     *   buf[0 ... 31]  = message
     *   buf[32 ... 63] = H(pk)
     */
    uint8_t buf[2 * KYBER_SYMBYTES];

    /*
     * kr:
     *
     *   kr[0 ... 31]  = shared secret
     *   kr[32 ... 63] = encryption coins
     */
    uint8_t kr[2 * KYBER_SYMBYTES];


    /*
     * --------------------------------------------------------
     * Step 1:
     * Copy random message.
     * --------------------------------------------------------
     */

    memcpy(
        buf,
        coins,
        KYBER_SYMBYTES
    );


    /*
     * DEBUG:
     * Print encapsulation message.
     */
    printf("[KEM] ENCAP MESSAGE: ");

    for (int i = 0; i < KYBER_SYMBYTES; i++) {

        printf(
            "%02X",
            buf[i]
        );

        if (i != KYBER_SYMBYTES - 1)
            printf(" ");
    }

    printf("\n");


    /*
     * DEBUG:
     * Print first 32 bytes of public key.
     */
    printf("[KEM] PK: ");

    for (int i = 0; i < 32; i++) {

        printf(
            "%02X",
            pk[i]
        );

        if (i != 31)
            printf(" ");
    }

    printf("\n");


    /*
     * Save the encapsulation message for debugging.
     */
    memcpy(
        debug_encap_message,
        buf,
        KYBER_SYMBYTES
    );


    /*
     * --------------------------------------------------------
     * Step 2:
     * Calculate H(pk).
     * --------------------------------------------------------
     */

    hash_h(
        buf + KYBER_SYMBYTES,
        pk,
        KYBER_PUBLICKEYBYTES
    );


    /*
     * DEBUG:
     * Print H(pk).
     */
    printf("[KEM] H(PK): ");

    for (int i = 0; i < KYBER_SYMBYTES; i++) {

        printf(
            "%02X",
            buf[KYBER_SYMBYTES + i]
        );

        if (i != KYBER_SYMBYTES - 1)
            printf(" ");
    }

    printf("\n");


    /*
     * --------------------------------------------------------
     * Step 3:
     * Derive:
     *
     *   kr[0 ... 31]  = shared secret
     *   kr[32 ... 63] = IND-CPA encryption coins
     * --------------------------------------------------------
     */

    hash_g(
        kr,
        buf,
        2 * KYBER_SYMBYTES
    );


    /*
     * --------------------------------------------------------
     * Step 4:
     * Perform IND-CPA encryption.
     * --------------------------------------------------------
     */

    PQCLEAN_MLKEM512_CLEAN_indcpa_enc(
        ct,
        buf,
        pk,
        kr + KYBER_SYMBYTES
    );


    /*
     * --------------------------------------------------------
     * Step 5:
     * Copy first half of kr as shared secret.
     * --------------------------------------------------------
     */

    memcpy(
        ss,
        kr,
        KYBER_SYMBYTES
    );

    return 0;
}


/*************************************************
* Name:        PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc
**************************************************/
int PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc(
    uint8_t *ct,
    uint8_t *ss,
    const uint8_t *pk
) {
    uint8_t coins[KYBER_SYMBYTES];

    /*
     * Generate random encapsulation message.
     */
    randombytes(
        coins,
        KYBER_SYMBYTES
    );

    /*
     * Perform deterministic encapsulation.
     */
    PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc_derand(
        ct,
        ss,
        pk,
        coins
    );

    return 0;
}


/*************************************************
* Name:        PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec
*
* Description:
*   ML-KEM decapsulation.
**************************************************/
int PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec(
    uint8_t *ss,
    const uint8_t *ct,
    const uint8_t *sk
) {
    int fail;

    /*
     * buf:
     *
     *   buf[0 ... 31]  = recovered message
     *   buf[32 ... 63] = H(pk)
     */
    uint8_t buf[2 * KYBER_SYMBYTES];

    /*
     * kr:
     *
     *   kr[0 ... 31]  = candidate shared secret
     *   kr[32 ... 63] = IND-CPA encryption coins
     */
    uint8_t kr[2 * KYBER_SYMBYTES];

    /*
     * Re-encrypted ciphertext used for verification.
     *
     * Exact ciphertext size:
     *
     *   ML-KEM-512 = 768 bytes
     */
    uint8_t cmp[
        KYBER_CIPHERTEXTBYTES
    ];


    /*
     * --------------------------------------------------------
     * Public key stored inside the secret key.
     * --------------------------------------------------------
     *
     * For ML-KEM-512:
     *
     *   IND-CPA secret key = 768 bytes
     *
     * Therefore:
     *
     *   pk = sk + 768
     */
    const uint8_t *pk =
        sk + KYBER_INDCPA_SECRETKEYBYTES;


    /*
     * --------------------------------------------------------
     * Step 1:
     * Recover original message from ciphertext.
     * --------------------------------------------------------
     */

    PQCLEAN_MLKEM512_CLEAN_indcpa_dec(
        buf,
        ct,
        sk
    );


    /*
     * DEBUG:
     * Print recovered message.
     */
    printf("[KEM] DECAP MESSAGE: ");

    for (int i = 0; i < KYBER_SYMBYTES; i++) {

        printf(
            "%02X",
            buf[i]
        );

        if (i != KYBER_SYMBYTES - 1)
            printf(" ");
    }

    printf("\n");


    /*
     * DEBUG:
     * Print stored H(pk).
     */
    printf("[KEM] STORED H(PK): ");

    for (int i = 0; i < KYBER_SYMBYTES; i++) {

        printf(
            "%02X",
            sk[
                KYBER_SECRETKEYBYTES
                - 2 * KYBER_SYMBYTES
                + i
            ]
        );

        if (i != KYBER_SYMBYTES - 1)
            printf(" ");
    }

    printf("\n");


    /*
     * DEBUG:
     * Print first 32 bytes of embedded public key.
     */
    printf("[KEM] EMBEDDED PK: ");

    for (int i = 0; i < 32; i++) {

        printf(
            "%02X",
            pk[i]
        );

        if (i != 31)
            printf(" ");
    }

    printf("\n");


    /*
     * Save recovered message for debugging.
     */
    memcpy(
        debug_decap_message,
        buf,
        KYBER_SYMBYTES
    );


    /*
     * --------------------------------------------------------
     * Step 2:
     * Restore H(pk).
     * --------------------------------------------------------
     *
     * Secret-key layout:
     *
     *   sk[0 ... 767]       = IND-CPA secret key
     *   sk[768 ... 1567]    = public key
     *   sk[1568 ... 1599]   = H(pk)
     *   sk[1600 ... 1631]   = z
     */

    memcpy(
        buf + KYBER_SYMBYTES,
        sk + KYBER_SECRETKEYBYTES
            - 2 * KYBER_SYMBYTES,
        KYBER_SYMBYTES
    );


    /*
     * --------------------------------------------------------
     * Step 3:
     * Derive candidate shared secret and encryption coins.
     * --------------------------------------------------------
     */

    hash_g(
        kr,
        buf,
        2 * KYBER_SYMBYTES
    );


    /*
     * --------------------------------------------------------
     * Step 4:
     * Re-encrypt recovered message.
     * --------------------------------------------------------
     */

    PQCLEAN_MLKEM512_CLEAN_indcpa_enc(
        cmp,
        buf,
        pk,
        kr + KYBER_SYMBYTES
    );


    /*
     * --------------------------------------------------------
     * Step 5:
     * Compare received ciphertext against reconstructed
     * ciphertext.
     *
     * fail = 0 -> VALID
     * fail = 1 -> INVALID
     * --------------------------------------------------------
     */

    fail =
        PQCLEAN_MLKEM512_CLEAN_verify(
            ct,
            cmp,
            KYBER_CIPHERTEXTBYTES
        );


    /*
     * Save verification result for the Arduino test.
     */
    debug_verify_fail = fail;


    /*
     * DEBUG:
     * Print verification result.
     */
    printf(
        "[ML-KEM] VERIFY FAIL = %d\n",
        fail
    );


    /*
     * --------------------------------------------------------
     * Step 6:
     * Compute rejection key.
     * --------------------------------------------------------
     *
     * This is required for implicit rejection.
     */

    rkprf(
        ss,
        sk + KYBER_SECRETKEYBYTES
            - KYBER_SYMBYTES,
        ct
    );


    /*
     * --------------------------------------------------------
     * Step 7:
     * If verification succeeded:
     *
     *     ss = kr
     *
     * If verification failed:
     *
     *     ss remains the rejection key.
     *
     * cmov() performs this without a normal branch.
     * --------------------------------------------------------
     */

    PQCLEAN_MLKEM512_CLEAN_cmov(
        ss,
        kr,
        KYBER_SYMBYTES,
        (uint8_t)(1 - fail)
    );


    return 0;
}


/* ============================================================
 * DEBUG GETTER FUNCTIONS
 * ============================================================
 */


/*************************************************
* Name:        mlkemDebugGetEncapMessage
*
* Description:
*   Copy encapsulation message into caller buffer.
**************************************************/
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


/*************************************************
* Name:        mlkemDebugGetDecapMessage
*
* Description:
*   Copy decapsulation recovered message
*   into caller buffer.
**************************************************/
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


/*************************************************
* Name:        mlkemDebugGetVerifyFail
*
* Description:
*   Return the verification result from the
*   most recent decapsulation.
*
*   Return value:
*
*       -1 = decapsulation has not been executed
*        0 = verification PASS
*        1 = verification FAIL
**************************************************/
int mlkemDebugGetVerifyFail(void)
{
    return debug_verify_fail;
}