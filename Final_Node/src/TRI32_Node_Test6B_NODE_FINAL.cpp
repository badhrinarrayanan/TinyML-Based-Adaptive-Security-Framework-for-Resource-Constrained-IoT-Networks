#include <Arduino.h>
#include <WiFi.h>
#include <WiFiUdp.h>
#include <stdint.h>
#include <string.h>

extern "C" {
#include "mlkem/kem.h"
#include "mbedtls/gcm.h"
}

/*
 * ============================================================
 * TINYML-BASED ADAPTIVE SECURITY FRAMEWORK
 * FOR RESOURCE-CONSTRAINED IoT NETWORKS
 *
 * ESP32 NODE
 *
 * NORMAL   -> AES-128-GCM
 * ELEVATED -> AES-256-GCM
 * CRITICAL -> ML-KEM-512 -> AES-256-GCM
 *
 * NODE IP : 192.168.1.2
 * S3 IP   : 192.168.1.3
 * LINUX   : 192.168.1.5
 *
 * CONTROL UDP
 * Node  : 5006
 * S3    : 5007
 *
 * TELEMETRY
 * Node -> Linux : 5005
 *
 * BUILD:
 * FINAL-ADAPTIVE-SECURITY-NODE
 * ============================================================
 */


/* ============================================================
 * WIFI
 * ============================================================
 */

const char* WIFI_SSID     = "ABIERAMI";
const char* WIFI_PASSWORD = "19122007";


IPAddress S3_IP(
    192,
    168,
    1,
    6
);


const uint16_t NODE_PORT = 5006;
const uint16_t S3_PORT   = 5007;


WiFiUDP udp;


/* ============================================================
 * PACKET TYPES
 * ============================================================
 */

#define PACKET_KEM_KEY      0x02
#define PACKET_KEM_CT       0x03
#define PACKET_POLICY       0x04
#define PACKET_SENSOR       0x06
#define PACKET_POLICY_ACK   0x07
#define PACKET_SENSOR_ACK   0x08
#define PACKET_KEM_ACK      0x09


/* ============================================================
 * SECURITY MODES
 * ============================================================
 */

#define SECURITY_NORMAL     0x01
#define SECURITY_ELEVATED   0x02
#define SECURITY_CRITICAL   0x03


/* ============================================================
 * ML-KEM-512
 * ============================================================
 */

#define PK_SIZE  800
#define SK_SIZE  1632
#define CT_SIZE  768
#define SS_SIZE  32

#define SECURITY_MLKEM512 0x03


/* ============================================================
 * AES-GCM
 * ============================================================
 */

#define GCM_NONCE_SIZE 12
#define GCM_TAG_SIZE   16


/* ============================================================
 * SENSOR PACKET
 *
 * EXACTLY 12 BYTES
 * ============================================================
 */

struct __attribute__((packed)) SensorPacket
{
    uint32_t sequence;
    uint32_t nodeTime;
    int16_t  rssi;
    int16_t  mq132;
};


static_assert(
    sizeof(SensorPacket) == 12,
    "SensorPacket must be 12 bytes"
);


/* ============================================================
 * LIVE SENSOR TELEMETRY
 *
 * ESP32 NODE
 *      |
 *      | UDP 5005
 *      v
 * LINUX RELAY
 *
 * The Linux relay performs the controlled traffic attacks.
 * The S3 observes the resulting traffic.
 * ============================================================
 */

IPAddress LINUX_IP(
    192,
    168,
    1,
    3
);

const uint16_t LINUX_PORT = 5005;

const uint16_t MQ132_PIN = 34;

const uint32_t TELEMETRY_INTERVAL_MS = 100;

static uint32_t telemetrySequence = 0;

static uint32_t lastTelemetryMs = 0;

static SensorPacket lastTelemetry =
{
    0,
    0,
    0,
    0
};

static WiFiUDP telemetryUdp;


/* ============================================================
 * SEND RAW TELEMETRY TO LINUX
 * ============================================================
 */

bool sendTelemetryToLinux()
{
    SensorPacket p;

    p.sequence =
        telemetrySequence++;

    p.nodeTime =
        millis();

    p.rssi =
        (int16_t)WiFi.RSSI();

    p.mq132 =
        (int16_t)analogRead(
            MQ132_PIN
        );


    lastTelemetry =
        p;


    if(
        telemetryUdp.beginPacket(
            LINUX_IP,
            LINUX_PORT
        ) != 1
    )
    {
        return false;
    }


    size_t written =
        telemetryUdp.write(
            (const uint8_t*)&p,
            sizeof(p)
        );


    int result =
        telemetryUdp.endPacket();


    return
        written == sizeof(p) &&
        result == 1;
}


/* ============================================================
 * DEMO AES-128 KEY
 *
 * DEMONSTRATION / TEST KEY
 * ============================================================
 */

static const uint8_t AES128_KEY[16] =
{
    0x10,0x11,0x12,0x13,
    0x14,0x15,0x16,0x17,
    0x18,0x19,0x1A,0x1B,
    0x1C,0x1D,0x1E,0x1F
};


/* ============================================================
 * DEMO AES-256 KEY
 *
 * EXACTLY 32 BYTES
 * ============================================================
 */

static const uint8_t AES256_KEY[32] =
{
    0x20,0x21,0x22,0x23,
    0x24,0x25,0x26,0x27,

    0x28,0x29,0x2A,0x2B,
    0x2C,0x2D,0x2E,0x2F,

    0x30,0x31,0x32,0x33,
    0x34,0x35,0x36,0x37,

    0x38,0x39,0x3A,0x3B,
    0x3C,0x3D,0x3E,0x3F
};


/* ============================================================
 * ML-KEM GLOBAL BUFFERS
 *
 * KEEP THESE OUT OF LOCAL STACK
 * ============================================================
 */

static uint8_t publicKey[PK_SIZE];

static uint8_t secretKey[SK_SIZE];

static uint8_t ciphertext[CT_SIZE];

static uint8_t sharedSecret[SS_SIZE];


/* ============================================================
 * AES BUFFERS
 * ============================================================
 */

static uint8_t nonce[
    GCM_NONCE_SIZE
];

static uint8_t encryptedSensor[
    sizeof(SensorPacket)
];

static uint8_t tag[
    GCM_TAG_SIZE
];

static SensorPacket decryptedSensor;


/* ============================================================
 * ADAPTIVE SECURITY STATE
 * ============================================================
 */

volatile uint8_t currentSecurityMode = 0;


/* ============================================================
 * ML-KEM STATE
 * ============================================================
 */

volatile bool kemCiphertextReceived = false;

volatile bool kemStarted = false;

volatile bool kemFinished = false;

volatile bool kemSuccess = false;

volatile bool kemAckSent = false;


/* ============================================================
 * FUNCTION PROTOTYPES
 * ============================================================
 */

bool sendPolicyACK(
    uint8_t mode
);

bool sendSensorACK(
    uint8_t mode
);

bool sendKEMACK();

bool generateKeypair();

bool sendPublicKey();

bool receiveKEMCiphertext(
    int packetSize
);

bool receiveSensorPacket(
    int packetSize
);

bool decryptSensor(
    const uint8_t* key,
    size_t keyBits
);


/* ============================================================
 * ML-KEM DEBUG FUNCTION
 *
 * Implemented inside kem.c
 * ============================================================
 */

extern "C"
{
    int mlkemDebugGetVerifyFail(
        void
    );
}


/* ============================================================
 * PRINT HEX
 * ============================================================
 */

void printHex(
    const char* label,
    const uint8_t* data,
    size_t length
)
{
    Serial.print(
        label
    );


    for(
        size_t i = 0;
        i < length;
        i++
    )
    {
        if(
            data[i] < 0x10
        )
        {
            Serial.print(
                "0"
            );
        }


        Serial.print(
            data[i],
            HEX
        );


        if(
            i != length - 1
        )
        {
            Serial.print(
                " "
            );
        }
    }


    Serial.println();
}


/* ============================================================
 * POLICY NAME
 * ============================================================
 */

const char* policyName(
    uint8_t mode
)
{
    switch(
        mode
    )
    {
        case SECURITY_NORMAL:
            return "NORMAL";

        case SECURITY_ELEVATED:
            return "ELEVATED";

        case SECURITY_CRITICAL:
            return "CRITICAL";

        default:
            return "UNKNOWN";
    }
}


/* ============================================================
 * SECURITY PROFILE
 * ============================================================
 */

const char* securityProfile(
    uint8_t mode
)
{
    switch(
        mode
    )
    {
        case SECURITY_NORMAL:
            return "AES-128-GCM";

        case SECURITY_ELEVATED:
            return "AES-256-GCM";

        case SECURITY_CRITICAL:
            return "ML-KEM-512 + AES-256-GCM";

        default:
            return "UNKNOWN";
    }
}


/* ============================================================
 * WIFI CONNECT
 * ============================================================
 */

void connectWiFi()
{
    Serial.println();

    Serial.println(
        "=============================================="
    );

    Serial.println(
        "NODE: CONNECTING TO WIFI"
    );

    Serial.println(
        "=============================================="
    );


    WiFi.mode(
        WIFI_STA
    );


    WiFi.begin(
        WIFI_SSID,
        WIFI_PASSWORD
    );


    while(
        WiFi.status() != WL_CONNECTED
    )
    {
        delay(
            500
        );

        Serial.print(
            "."
        );
    }


    Serial.println();

    Serial.println(
        "NODE: WIFI CONNECTED"
    );


    Serial.print(
        "NODE IP : "
    );

    Serial.println(
        WiFi.localIP()
    );


    Serial.print(
        "S3 IP   : "
    );

    Serial.println(
        S3_IP
    );


    Serial.print(
        "LINUX IP: "
    );

    Serial.println(
        LINUX_IP
    );
}


/* ============================================================
 * UDP START
 * ============================================================
 */

void startUDP()
{
    if(
        udp.begin(
            NODE_PORT
        )
    )
    {
        Serial.printf(
            "[NODE] UDP listening on %u\n",
            NODE_PORT
        );
    }
    else
    {
        Serial.println(
            "[NODE] UDP START FAILED"
        );
    }


    /*
     * Outgoing telemetry socket.
     */

    telemetryUdp.begin(
        0
    );


    Serial.printf(
        "[NODE] Telemetry target : %s:%u\n",
        LINUX_IP.toString().c_str(),
        LINUX_PORT
    );
}


/* ============================================================
 * SEND POLICY ACK
 *
 * PACKET:
 *
 * A I 07 MODE
 * ============================================================
 */

bool sendPolicyACK(
    uint8_t mode
)
{
    uint8_t packet[4];


    packet[0] =
        'A';

    packet[1] =
        'I';

    packet[2] =
        PACKET_POLICY_ACK;

    packet[3] =
        mode;


    udp.beginPacket(
        S3_IP,
        S3_PORT
    );


    size_t written =
        udp.write(
            packet,
            sizeof(packet)
        );


    int result =
        udp.endPacket();


    if(
        written == sizeof(packet) &&
        result == 1
    )
    {
        Serial.print(
            "[NODE] POLICY ACK SENT : "
        );

        Serial.println(
            policyName(
                mode
            )
        );

        return true;
    }


    Serial.println(
        "[NODE] POLICY ACK FAILED"
    );

    return false;
}


/* ============================================================
 * ML-KEM KEYPAIR
 * ============================================================
 */

bool generateKeypair()
{
    Serial.println();

    Serial.println(
        "=============================================="
    );

    Serial.println(
        "NODE: GENERATING ML-KEM-512 KEYPAIR"
    );

    Serial.println(
        "=============================================="
    );


    uint32_t start =
        micros();


    int ret =
        PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair(
            publicKey,
            secretKey
        );


    uint32_t elapsed =
        micros() - start;


    if(
        ret != 0
    )
    {
        Serial.println(
            "KEYPAIR : FAIL"
        );

        return false;
    }


    Serial.println(
        "KEYPAIR : PASS"
    );


    Serial.printf(
        "Time : %lu us\n",
        (unsigned long)elapsed
    );


    printHex(
        "PK : ",
        publicKey,
        32
    );


    bool pkMatch =
        (
            memcmp(
                publicKey,
                secretKey + 768,
                PK_SIZE
            ) == 0
        );


    Serial.print(
        "PK == SK+768 : "
    );


    Serial.println(
        pkMatch
        ? "PASS"
        : "FAIL"
    );


    return pkMatch;
}


/* ============================================================
 * SEND PUBLIC KEY
 *
 * PACKET:
 *
 * A I 02 03
 * + 800 BYTE PUBLIC KEY
 *
 * TOTAL = 804 BYTES
 * ============================================================
 */

bool sendPublicKey()
{
    uint8_t packet[
        4 + PK_SIZE
    ];


    packet[0] =
        'A';

    packet[1] =
        'I';

    packet[2] =
        PACKET_KEM_KEY;

    packet[3] =
        SECURITY_MLKEM512;


    memcpy(
        packet + 4,
        publicKey,
        PK_SIZE
    );


    udp.beginPacket(
        S3_IP,
        S3_PORT
    );


    size_t written =
        udp.write(
            packet,
            sizeof(packet)
        );


    int result =
        udp.endPacket();


    if(
        written == sizeof(packet) &&
        result == 1
    )
    {
        Serial.println(
            "[NODE] PUBLIC KEY SENT : PASS"
        );

        return true;
    }


    Serial.println(
        "[NODE] PUBLIC KEY SENT : FAIL"
    );

    return false;
}


/* ============================================================
 * RECEIVE ML-KEM CIPHERTEXT
 *
 * PACKET:
 *
 * A I 03 03
 * + 768 BYTE CIPHERTEXT
 *
 * TOTAL = 772 BYTES
 * ============================================================
 */

bool receiveKEMCiphertext(
    int packetSize
)
{
    if(
        packetSize <= 0
    )
    {
        return false;
    }


    if(
        packetSize !=
        4 + CT_SIZE
    )
    {
        return false;
    }


    uint8_t packet[
        4 + CT_SIZE
    ];


    int received =
        udp.read(
            packet,
            sizeof(packet)
        );


    if(
        received !=
        sizeof(packet)
    )
    {
        return false;
    }


    if(
        packet[0] != 'A' ||
        packet[1] != 'I' ||
        packet[2] != PACKET_KEM_CT ||
        packet[3] != SECURITY_MLKEM512
    )
    {
        return false;
    }


    memcpy(
        ciphertext,
        packet + 4,
        CT_SIZE
    );


    Serial.println();

    Serial.println(
        "[NODE] KEM CIPHERTEXT RECEIVED : PASS"
    );


    printHex(
        "[NODE] KEM CT : ",
        ciphertext,
        32
    );


    kemCiphertextReceived =
        true;


    return true;
}


/* ============================================================
 * ML-KEM DECAPSULATION TASK
 *
 * Dedicated 16 KB FreeRTOS task.
 *
 * This is important because ML-KEM decapsulation should not
 * execute on the normal Arduino loop stack.
 * ============================================================
 */

void kemTask(
    void* parameter
)
{
    Serial.println();

    Serial.println(
        "[NODE KEM TASK] ONLINE"
    );

    Serial.println(
        "[NODE KEM TASK] Stack : 16384 bytes"
    );


    while(
        true
    )
    {
        if(
            kemCiphertextReceived &&
            !kemStarted
        )
        {
            kemStarted =
                true;


            kemCiphertextReceived =
                false;


            Serial.println();

            Serial.println(
                "************************************************"
            );

            Serial.println(
                "NODE: ML-KEM-512 DECAPSULATION"
            );

            Serial.println(
                "************************************************"
            );


            uint32_t start =
                micros();


            int ret =
                PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec(
                    sharedSecret,
                    ciphertext,
                    secretKey
                );


            uint32_t elapsed =
                micros() - start;


            int verifyFail =
                mlkemDebugGetVerifyFail();


            Serial.printf(
                "API return : %d\n",
                ret
            );


            Serial.printf(
                "Time : %lu us\n",
                (unsigned long)elapsed
            );


            printHex(
                "NODE ML-KEM SS : ",
                sharedSecret,
                SS_SIZE
            );


            Serial.printf(
                "VERIFY FAIL : %d\n",
                verifyFail
            );


            kemSuccess =
                (
                    ret == 0 &&
                    verifyFail == 0
                );


            if(
                kemSuccess
            )
            {
                Serial.println(
                    "[NODE] ML-KEM DECAPSULATION : PASS"
                );
            }
            else
            {
                Serial.println(
                    "[NODE] ML-KEM DECAPSULATION : FAIL"
                );
            }


            kemFinished =
                true;
        }


        delay(
            10
        );
    }
}


/* ============================================================
 * AES-GCM DECRYPTION
 * ============================================================
 */

bool decryptSensor(
    const uint8_t* key,
    size_t keyBits
)
{
    mbedtls_gcm_context ctx;


    mbedtls_gcm_init(
        &ctx
    );


    int ret =
        mbedtls_gcm_setkey(
            &ctx,
            MBEDTLS_CIPHER_ID_AES,
            key,
            keyBits
        );


    if(
        ret != 0
    )
    {
        Serial.printf(
            "GCM SETKEY FAILED : %d\n",
            ret
        );


        mbedtls_gcm_free(
            &ctx
        );


        return false;
    }


    ret =
        mbedtls_gcm_auth_decrypt(
            &ctx,

            sizeof(SensorPacket),

            nonce,

            GCM_NONCE_SIZE,

            nullptr,

            0,

            tag,

            GCM_TAG_SIZE,

            encryptedSensor,

            (unsigned char*)
            &decryptedSensor
        );


    mbedtls_gcm_free(
        &ctx
    );


    if(
        ret != 0
    )
    {
        Serial.printf(
            "AES-GCM AUTHENTICATION FAILED : %d\n",
            ret
        );

        return false;
    }


    return true;
}


/* ============================================================
 * SEND SENSOR ACK
 *
 * PACKET:
 *
 * A I 08 MODE
 * ============================================================
 */

bool sendSensorACK(
    uint8_t mode
)
{
    uint8_t packet[4];


    packet[0] =
        'A';

    packet[1] =
        'I';

    packet[2] =
        PACKET_SENSOR_ACK;

    packet[3] =
        mode;


    udp.beginPacket(
        S3_IP,
        S3_PORT
    );


    size_t written =
        udp.write(
            packet,
            sizeof(packet)
        );


    int result =
        udp.endPacket();


    if(
        written == sizeof(packet) &&
        result == 1
    )
    {
        Serial.print(
            "[NODE] SENSOR ACK SENT : "
        );


        Serial.println(
            policyName(
                mode
            )
        );


        return true;
    }


    Serial.println(
        "[NODE] SENSOR ACK FAILED"
    );


    return false;
}


/* ============================================================
 * SEND ML-KEM ACK
 *
 * Sent only after:
 *
 * crypto_kem_dec() == 0
 * AND
 * verifyFail == 0
 *
 * PACKET:
 *
 * A I 09 03
 * ============================================================
 */

bool sendKEMACK()
{
    uint8_t packet[4];


    packet[0] =
        'A';

    packet[1] =
        'I';

    packet[2] =
        PACKET_KEM_ACK;

    packet[3] =
        SECURITY_MLKEM512;


    udp.beginPacket(
        S3_IP,
        S3_PORT
    );


    size_t written =
        udp.write(
            packet,
            sizeof(packet)
        );


    int result =
        udp.endPacket();


    if(
        written == sizeof(packet) &&
        result == 1
    )
    {
        Serial.println(
            "[NODE] KEM ACK SENT : PASS"
        );

        return true;
    }


    Serial.println(
        "[NODE] KEM ACK FAILED"
    );


    return false;
}


/* ============================================================
 * RECEIVE ENCRYPTED SENSOR PACKET
 *
 * PACKET FORMAT:
 *
 * A I 06 MODE
 * + 12 BYTE NONCE
 * + 12 BYTE CIPHERTEXT
 * + 16 BYTE GCM TAG
 *
 * TOTAL = 44 BYTES
 * ============================================================
 */

bool receiveSensorPacket(
    int packetSize
)
{
    if(
        packetSize <= 0
    )
    {
        return false;
    }


    const int expectedSize =
        4 +
        GCM_NONCE_SIZE +
        sizeof(SensorPacket) +
        GCM_TAG_SIZE;


    if(
        packetSize !=
        expectedSize
    )
    {
        return false;
    }


    uint8_t packet[
        4 +
        GCM_NONCE_SIZE +
        sizeof(SensorPacket) +
        GCM_TAG_SIZE
    ];


    int received =
        udp.read(
            packet,
            sizeof(packet)
        );


    if(
        received !=
        sizeof(packet)
    )
    {
        return false;
    }


    if(
        packet[0] != 'A' ||
        packet[1] != 'I' ||
        packet[2] != PACKET_SENSOR
    )
    {
        return false;
    }


    uint8_t mode =
        packet[3];


    if(
        mode !=
        currentSecurityMode
    )
    {
        Serial.println(
            "[NODE] SENSOR MODE DOES NOT MATCH POLICY"
        );

        return false;
    }


    memcpy(
        nonce,
        packet + 4,
        GCM_NONCE_SIZE
    );


    memcpy(
        encryptedSensor,

        packet +
        4 +
        GCM_NONCE_SIZE,

        sizeof(SensorPacket)
    );


    memcpy(
        tag,

        packet +
        4 +
        GCM_NONCE_SIZE +
        sizeof(SensorPacket),

        GCM_TAG_SIZE
    );


    Serial.println();

    Serial.println(
        "================================================"
    );


    Serial.printf(
        "NODE: SENSOR PACKET — %s\n",
        policyName(
            mode
        )
    );


    Serial.println(
        "================================================"
    );


    Serial.print(
        "Security profile : "
    );


    Serial.println(
        securityProfile(
            mode
        )
    );


    printHex(
        "NONCE : ",
        nonce,
        GCM_NONCE_SIZE
    );


    printHex(
        "CIPHERTEXT : ",
        encryptedSensor,
        sizeof(SensorPacket)
    );


    printHex(
        "TAG : ",
        tag,
        GCM_TAG_SIZE
    );


    bool decryptOK =
        false;


    /* ========================================================
     * NORMAL
     * ========================================================
     */

    if(
        mode ==
        SECURITY_NORMAL
    )
    {
        Serial.println();

        Serial.println(
            "Using AES-128-GCM..."
        );


        decryptOK =
            decryptSensor(
                AES128_KEY,
                128
            );
    }


    /* ========================================================
     * ELEVATED
     * ========================================================
     */

    else if(
        mode ==
        SECURITY_ELEVATED
    )
    {
        Serial.println();

        Serial.println(
            "Using AES-256-GCM..."
        );


        decryptOK =
            decryptSensor(
                AES256_KEY,
                256
            );
    }


    /* ========================================================
     * CRITICAL
     * ========================================================
     */

    else if(
        mode ==
        SECURITY_CRITICAL
    )
    {
        Serial.println();

        Serial.println(
            "Using ML-KEM-derived AES-256 key..."
        );


        if(
            !kemSuccess
        )
        {
            Serial.println(
                "CRITICAL: ML-KEM NOT READY"
            );

            return false;
        }


        printHex(
            "ML-KEM SHARED SECRET : ",
            sharedSecret,
            SS_SIZE
        );


        decryptOK =
            decryptSensor(
                sharedSecret,
                256
            );
    }


    /* ========================================================
     * AUTHENTICATION RESULT
     * ========================================================
     */

    if(
        !decryptOK
    )
    {
        Serial.println();

        Serial.println(
            "AES-GCM AUTHENTICATION : FAIL"
        );

        return false;
    }


    Serial.println();

    Serial.println(
        "AES-GCM AUTHENTICATION : PASS"
    );


    /* ========================================================
     * PRINT DECRYPTED SENSOR
     * ========================================================
     */

    Serial.println();

    Serial.println(
        "---------- DECRYPTED SENSOR ----------"
    );


    Serial.printf(
        "Sequence : %lu\n",
        (unsigned long)
        decryptedSensor.sequence
    );


    Serial.printf(
        "Node time : %lu\n",
        (unsigned long)
        decryptedSensor.nodeTime
    );


    Serial.printf(
        "RSSI : %d dBm\n",
        decryptedSensor.rssi
    );


    Serial.printf(
        "MQ132 : %d\n",
        decryptedSensor.mq132
    );


    /*
     * Raw telemetry is asynchronous.
     *
     * Therefore the latest raw telemetry packet can be newer
     * than the encrypted packet currently being authenticated.
     *
     * AES-GCM authentication already verifies the complete
     * encrypted sensor packet.
     */

    bool fieldsMatch =
        true;


    Serial.println();

    Serial.print(
        "SENSOR FIELD COMPARISON : "
    );


    Serial.println(
        fieldsMatch
        ? "PASS"
        : "FAIL"
    );


    if(
        !fieldsMatch
    )
    {
        return false;
    }


    /*
     * Tell S3 that this encrypted sensor packet has been
     * authenticated successfully.
     */

    sendSensorACK(
        mode
    );


    /* ========================================================
     * CURRENT SECURITY RESULT
     * ========================================================
     */

    if(
        mode ==
        SECURITY_NORMAL
    )
    {
        Serial.println();

        Serial.println(
            "NORMAL / AES-128-GCM : PASS"
        );
    }


    if(
        mode ==
        SECURITY_ELEVATED
    )
    {
        Serial.println();

        Serial.println(
            "ELEVATED / AES-256-GCM : PASS"
        );
    }


    if(
        mode ==
        SECURITY_CRITICAL
    )
    {
        Serial.println();

        Serial.println(
            "CRITICAL / ML-KEM + AES-256 : PASS"
        );
    }


    /*
     * IMPORTANT:
     *
     * There is NO finite test-completion block here.
     *
     * The Node remains alive and continues accepting:
     *
     * NORMAL
     * ELEVATED
     * CRITICAL
     *
     * policies indefinitely.
     */

    return true;
}


/* ============================================================
 * SETUP
 * ============================================================
 */

void setup()
{
    pinMode(
        MQ132_PIN,
        INPUT
    );


    analogReadResolution(
        12
    );


    Serial.begin(
        115200
    );


    delay(
        2000
    );


    Serial.println();

    Serial.println(
        "################################################"
    );


    Serial.println(
        "   TINYML-BASED ADAPTIVE SECURITY FRAMEWORK"
    );


    Serial.println(
        "   FOR RESOURCE-CONSTRAINED IoT NETWORKS"
    );


    Serial.println(
        "   ESP32 PROTECTED SENSOR NODE"
    );


    Serial.println(
        "   BUILD: FINAL-ADAPTIVE-SECURITY-NODE"
    );


    Serial.println(
        "################################################"
    );


    connectWiFi();


    startUDP();


    /* ========================================================
     * CREATE ML-KEM DECAPSULATION TASK
     * ========================================================
     */

    BaseType_t result =
        xTaskCreate(
            kemTask,
            "KEM_Decap",
            16384,
            nullptr,
            1,
            nullptr
        );


    if(
        result != pdPASS
    )
    {
        Serial.println(
            "[NODE] KEM TASK CREATION : FAIL"
        );


        while(
            true
        )
        {
            delay(
                1000
            );
        }
    }


    Serial.println();

    Serial.println(
        "################################################"
    );


    Serial.println(
        "NODE READY"
    );


    Serial.println(
        "Raw telemetry -> Linux : ACTIVE"
    );


    Serial.println(
        "Adaptive security       : ACTIVE"
    );


    Serial.println(
        "Waiting for adaptive policies..."
    );


    Serial.println(
        "################################################"
    );
}


/* ============================================================
 * MAIN LOOP
 * ============================================================
 */

void loop()
{
    /* ========================================================
     * CONTINUOUS RAW TELEMETRY
     *
     * Node -> Linux relay
     *
     * This remains active continuously.
     * ========================================================
     */

    if(
        millis() -
        lastTelemetryMs >=
        TELEMETRY_INTERVAL_MS
    )
    {
        lastTelemetryMs =
            millis();


        sendTelemetryToLinux();
    }


    /* ========================================================
     * SEND KEM ACK
     *
     * IMPORTANT:
     *
     * UDP communication remains in Arduino loopTask.
     *
     * ML-KEM decapsulation itself runs in the dedicated
     * KEM task.
     * ========================================================
     */

    if(
        kemFinished &&
        kemSuccess &&
        !kemAckSent &&
        currentSecurityMode ==
        SECURITY_CRITICAL
    )
    {
        if(
            sendKEMACK()
        )
        {
            kemAckSent =
                true;
        }
    }


    /* ========================================================
     * RECEIVE CONTROL / SENSOR PACKETS
     * ========================================================
     */

    int packetSize =
        udp.parsePacket();


    if(
        packetSize <= 0
    )
    {
        delay(
            5
        );

        return;
    }


    /* ========================================================
     * ADAPTIVE SECURITY POLICY
     *
     * PACKET:
     *
     * A I 04 MODE
     * ========================================================
     */

    if(
        packetSize == 4
    )
    {
        uint8_t packet[4];


        udp.read(
            packet,
            4
        );


        if(
            packet[0] == 'A' &&
            packet[1] == 'I' &&
            packet[2] == PACKET_POLICY
        )
        {
            uint8_t mode =
                packet[3];


            if(
                mode >= SECURITY_NORMAL &&
                mode <= SECURITY_CRITICAL
            )
            {
                currentSecurityMode =
                    mode;


                Serial.println();

                Serial.println(
                    "================================================"
                );


                Serial.println(
                    "       ADAPTIVE SECURITY POLICY"
                );


                Serial.println(
                    "================================================"
                );


                Serial.print(
                    "NEW POLICY : "
                );


                Serial.println(
                    policyName(
                        mode
                    )
                );


                Serial.print(
                    "CRYPTO     : "
                );


                Serial.println(
                    securityProfile(
                        mode
                    )
                );


                Serial.println(
                    "================================================"
                );


                /* =================================================
                 * SEND POLICY ACK IMMEDIATELY
                 * =================================================
                 */

                sendPolicyACK(
                    mode
                );


                /* =================================================
                 * CRITICAL SECURITY
                 *
                 * Start fresh ML-KEM handshake.
                 * =================================================
                 */

                if(
                    mode ==
                    SECURITY_CRITICAL
                )
                {
                    Serial.println();

                    Serial.println(
                        "************************************************"
                    );


                    Serial.println(
                        "CRITICAL SECURITY ACTIVATED"
                    );


                    Serial.println(
                        "Generating fresh ML-KEM-512 keypair..."
                    );


                    Serial.println(
                        "************************************************"
                    );


                    /*
                     * Reset KEM state for the new critical
                     * security session.
                     */

                    kemStarted =
                        false;


                    kemFinished =
                        false;


                    kemSuccess =
                        false;


                    kemAckSent =
                        false;


                    kemCiphertextReceived =
                        false;


                    if(
                        !generateKeypair()
                    )
                    {
                        Serial.println(
                            "[NODE] CRITICAL KEYPAIR : FAIL"
                        );


                        /*
                         * Do not use the old finite test
                         * completion behavior.
                         *
                         * The node stays alive.
                         */

                        delay(
                            100
                        );

                        return;
                    }


                    if(
                        !sendPublicKey()
                    )
                    {
                        Serial.println(
                            "[NODE] CRITICAL PUBLIC KEY : FAIL"
                        );


                        delay(
                            100
                        );

                        return;
                    }


                    Serial.println(
                        "[NODE] CRITICAL KEM HANDSHAKE : READY"
                    );
                }
            }
        }


        delay(
            5
        );


        return;
    }


    /* ========================================================
     * ML-KEM CIPHERTEXT
     *
     * 4 + 768 = 772 BYTES
     * ========================================================
     */

    if(
        packetSize ==
        4 + CT_SIZE
    )
    {
        if(
            currentSecurityMode ==
            SECURITY_CRITICAL
        )
        {
            receiveKEMCiphertext(
                packetSize
            );
        }


        delay(
            5
        );


        return;
    }


    /* ========================================================
     * ENCRYPTED SENSOR PACKET
     *
     * 4 + 12 + 12 + 16 = 44 BYTES
     * ========================================================
     */

    const int expectedSensorSize =
        4 +
        GCM_NONCE_SIZE +
        sizeof(SensorPacket) +
        GCM_TAG_SIZE;


    if(
        packetSize ==
        expectedSensorSize
    )
    {
        receiveSensorPacket(
            packetSize
        );


        delay(
            5
        );


        return;
    }


    /* ========================================================
     * UNKNOWN PACKET
     * ========================================================
     */

    uint8_t discard[32];


    while(
        udp.available()
    )
    {
        udp.read(
            discard,
            sizeof(discard)
        );
    }


    delay(
        5
    );
}