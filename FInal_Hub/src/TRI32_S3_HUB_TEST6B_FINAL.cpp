#include <Arduino.h>
#include <WiFi.h>
#include <WiFiUdp.h>
#include <stdint.h>
#include <string.h>
#include <math.h>

#include "adaptive_threat_xgb.h"

extern "C" {
#include "mlkem/kem.h"
#include "mbedtls/gcm.h"
}


/*
 * ============================================================
 * TINYML-BASED ADAPTIVE SECURITY FRAMEWORK
 * FOR RESOURCE-CONSTRAINED IoT NETWORKS
 *
 * ESP32-S3 EDGE-AI HUB
 *
 * NORMAL   -> AES-128-GCM
 * ELEVATED -> AES-256-GCM
 * CRITICAL -> ML-KEM-512 -> AES-256-GCM
 *
 * S3 IP   : 192.168.1.3
 * NODE IP : 192.168.1.2
 * LINUX   : 192.168.1.5
 *
 * CONTROL:
 *   Node <-> S3 : UDP 5007
 *
 * TELEMETRY:
 *   Linux -> S3 : UDP 5008
 *
 * CONTINUOUS OPERATION:
 *   S3 continuously encrypts the latest sensor data
 *   using the currently active security policy.
 *
 * BUILD:
 * FINAL-ADAPTIVE-SECURITY-HUB
 *
 * ============================================================
 */


/* ============================================================
 * WIFI
 * ============================================================
 */

const char* WIFI_SSID     = "ABIERAMI";
const char* WIFI_PASSWORD = "19122007";


IPAddress NODE_IP(
    192,
    168,
    1,
    2
);


/* ============================================================
 * UDP PORTS
 * ============================================================
 *
 * CONTROL:
 *   S3 listens on 5007
 *
 * TELEMETRY:
 *   S3 listens on 5008
 *
 * ============================================================
 */

const uint16_t NODE_PORT      = 5006;
const uint16_t S3_PORT        = 5007;
const uint16_t TELEMETRY_PORT = 5008;


WiFiUDP udp;
WiFiUDP telemetryUdp;


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

#define PK_SIZE             800
#define CT_SIZE             768
#define SS_SIZE             32

#define SECURITY_MLKEM512   0x03


/* ============================================================
 * AES-GCM
 * ============================================================
 */

#define GCM_NONCE_SIZE      12
#define GCM_TAG_SIZE        16


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
 * DEMO AES-128 KEY
 *
 * DEMONSTRATION / TEST KEY
 * ============================================================
 */

static const uint8_t AES128_KEY[16] =
{
    0x10, 0x11, 0x12, 0x13,
    0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1A, 0x1B,
    0x1C, 0x1D, 0x1E, 0x1F
};


/* ============================================================
 * DEMO AES-256 KEY
 *
 * DEMONSTRATION / TEST KEY
 * ============================================================
 */

static const uint8_t AES256_KEY[32] =
{
    0x20, 0x21, 0x22, 0x23,
    0x24, 0x25, 0x26, 0x27,

    0x28, 0x29, 0x2A, 0x2B,
    0x2C, 0x2D, 0x2E, 0x2F,

    0x30, 0x31, 0x32, 0x33,
    0x34, 0x35, 0x36, 0x37,

    0x38, 0x39, 0x3A, 0x3B,
    0x3C, 0x3D, 0x3E, 0x3F
};


/* ============================================================
 * ML-KEM GLOBAL BUFFERS
 *
 * KEEP OUT OF LOCAL STACK
 * ============================================================
 */

static uint8_t publicKey[PK_SIZE];

static uint8_t ciphertext[CT_SIZE];

static uint8_t sharedSecret[SS_SIZE];


/* ============================================================
 * AES BUFFERS
 * ============================================================
 */

static uint8_t nonce[GCM_NONCE_SIZE];

static uint8_t encryptedSensor[
    sizeof(SensorPacket)
];

static uint8_t tag[GCM_TAG_SIZE];


/* ============================================================
 * LATEST REAL SENSOR DATA
 *
 * This is updated from the Linux telemetry stream.
 *
 * No fake test sensor packet is transmitted.
 * ============================================================
 */

static SensorPacket sensorData =
{
    0,
    0,
    0,
    0
};


static bool haveSensorData = false;


/* ============================================================
 * KEM STATE
 * ============================================================
 */

volatile bool pkReceived    = false;
volatile bool kemFinished   = false;
volatile bool kemSuccess    = false;


/* ============================================================
 * ACTIVE SECURITY STATE
 * ============================================================
 */

static int currentThreatLevel = -1;

static uint8_t currentSecurityPolicy = 0;


/* ============================================================
 * CONTINUOUS ENCRYPTION
 * ============================================================
 *
 * S3 sends encrypted sensor data periodically after a
 * security profile has been established.
 *
 * ML-KEM is NOT repeated for every sensor packet.
 *
 * ============================================================
 */

const uint32_t ENCRYPTED_SENSOR_INTERVAL_MS = 500;

static uint32_t lastEncryptedSensorMs = 0;


/* ============================================================
 * FUNCTION PROTOTYPES
 * ============================================================
 */

bool sendPolicy(
    uint8_t policy
);

bool receivePolicyACK(
    uint8_t expectedPolicy,
    uint32_t timeoutMs
);

bool sendPolicyAndWait(
    uint8_t policy
);

bool receiveSensorACK(
    uint8_t expectedMode,
    uint32_t timeoutMs
);

bool receiveKEMACK(
    uint32_t timeoutMs
);

bool receivePublicKey(
    uint32_t timeoutMs
);

bool startKEMTask();

bool aesEncrypt(
    const uint8_t* key,
    size_t keyBits
);

bool sendEncryptedSensorPacket(
    uint8_t mode,
    bool waitForACK
);

static bool activateCriticalSecurity();

static void runLiveInference();
static void mlInferenceTask(void *parameter);

static void processLiveSensor(
    const uint8_t* data,
    int len
);

static void serviceTelemetryDuringWait();

/* Set when a complete ML window is collected while a security
 * transition is still in progress. The main loop will run the
 * inference after the transition returns. */
static volatile bool pendingMLInference = false;

/* Dedicated FreeRTOS task state for XGBoost inference.
 * The generated 4-class XGBoost code uses many local double
 * variables, so inference must NOT run on loopTask. */
static volatile bool mlInferenceFinished = false;
static volatile bool mlInferenceTaskOK = false;
static volatile uint32_t mlInferenceElapsedUs = 0;


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
    Serial.print(label);

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
            Serial.print("0");
        }

        Serial.print(
            data[i],
            HEX
        );

        if(
            i != length - 1
        )
        {
            Serial.print(" ");
        }
    }

    Serial.println();
}


/* ============================================================
 * POLICY NAME
 * ============================================================
 */

const char* policyName(
    uint8_t policy
)
{
    switch(policy)
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
    uint8_t policy
)
{
    switch(policy)
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
        "S3: CONNECTING TO WIFI"
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
        delay(500);

        Serial.print(".");
    }


    Serial.println();

    Serial.println(
        "S3: WIFI CONNECTED"
    );


    Serial.print(
        "S3 IP   : "
    );

    Serial.println(
        WiFi.localIP()
    );


    Serial.print(
        "NODE IP : "
    );

    Serial.println(
        NODE_IP
    );
}


/* ============================================================
 * UDP START
 * ============================================================
 */

bool startUDP()
{
    bool controlOK =
        udp.begin(
            S3_PORT
        );


    bool telemetryOK =
        telemetryUdp.begin(
            TELEMETRY_PORT
        );


    if(
        controlOK &&
        telemetryOK
    )
    {
        Serial.printf(
            "[S3] CONTROL UDP listening on %u\n",
            S3_PORT
        );

        Serial.printf(
            "[S3] TELEMETRY UDP listening on %u\n",
            TELEMETRY_PORT
        );

        return true;
    }


    Serial.println(
        "[S3] UDP START FAILED"
    );


    Serial.printf(
        "[S3] control=%s telemetry=%s\n",
        controlOK ? "OK" : "FAIL",
        telemetryOK ? "OK" : "FAIL"
    );


    return false;
}


/* ============================================================
 * SEND POLICY
 * ============================================================
 */

bool sendPolicy(
    uint8_t policy
)
{
    uint8_t packet[4];


    packet[0] = 'A';
    packet[1] = 'I';
    packet[2] = PACKET_POLICY;
    packet[3] = policy;


    Serial.println();

    Serial.println(
        "----------------------------------------------"
    );


    Serial.printf(
        "[S3] POLICY : %s\n",
        policyName(policy)
    );


    Serial.printf(
        "[S3] MODE : %u\n",
        policy
    );


    if(
        udp.beginPacket(
            NODE_IP,
            NODE_PORT
        ) != 1
    )
    {
        Serial.println(
            "[S3] POLICY PACKET START FAILED"
        );

        return false;
    }


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
            "[S3] POLICY SENT : PASS"
        );

        return true;
    }


    Serial.println(
        "[S3] POLICY SENT : FAIL"
    );


    return false;
}


/* ============================================================
 * RECEIVE POLICY ACK
 * ============================================================
 */

bool receivePolicyACK(
    uint8_t expectedPolicy,
    uint32_t timeoutMs
)
{
    uint32_t start =
        millis();


    while(
        millis() - start <
        timeoutMs
    )
    {
        serviceTelemetryDuringWait();

        int packetSize =
            udp.parsePacket();


        if(
            packetSize <= 0
        )
        {
            delay(5);

            continue;
        }


        if(
            packetSize != 4
        )
        {
            uint8_t discard[1024];

            while(
                udp.available()
            )
            {
                udp.read(
                    discard,
                    sizeof(discard)
                );
            }

            continue;
        }


        uint8_t packet[4];


        int received =
            udp.read(
                packet,
                sizeof(packet)
            );


        if(
            received != 4
        )
        {
            continue;
        }


        if(
            packet[0] == 'A' &&
            packet[1] == 'I' &&
            packet[2] == PACKET_POLICY_ACK
        )
        {
            uint8_t mode =
                packet[3];


            if(
                mode == expectedPolicy
            )
            {
                Serial.printf(
                    "[S3] POLICY ACK RECEIVED : %s\n",
                    policyName(mode)
                );

                return true;
            }
        }
    }


    Serial.printf(
        "[S3] POLICY ACK TIMEOUT : %s\n",
        policyName(expectedPolicy)
    );


    return false;
}


/* ============================================================
 * SEND POLICY + WAIT FOR ACK
 * ============================================================
 */

bool sendPolicyAndWait(
    uint8_t policy
)
{
    if(
        !sendPolicy(
            policy
        )
    )
    {
        return false;
    }


    delay(100);


    if(
        !receivePolicyACK(
            policy,
            5000
        )
    )
    {
        return false;
    }


    Serial.println(
        "[S3] POLICY SYNCHRONIZATION : PASS"
    );


    return true;
}


/* ============================================================
 * RECEIVE SENSOR ACK
 * ============================================================
 */

bool receiveSensorACK(
    uint8_t expectedMode,
    uint32_t timeoutMs
)
{
    uint32_t start =
        millis();


    while(
        millis() - start <
        timeoutMs
    )
    {
        serviceTelemetryDuringWait();

        int packetSize =
            udp.parsePacket();


        if(
            packetSize <= 0
        )
        {
            delay(5);

            continue;
        }


        if(
            packetSize != 4
        )
        {
            uint8_t discard[1024];

            while(
                udp.available()
            )
            {
                udp.read(
                    discard,
                    sizeof(discard)
                );
            }

            continue;
        }


        uint8_t packet[4];


        if(
            udp.read(
                packet,
                4
            ) != 4
        )
        {
            continue;
        }


        if(
            packet[0] == 'A' &&
            packet[1] == 'I' &&
            packet[2] == PACKET_SENSOR_ACK &&
            packet[3] == expectedMode
        )
        {
            Serial.printf(
                "[S3] SENSOR ACK RECEIVED : %s\n",
                policyName(expectedMode)
            );

            Serial.println(
                "[S3] SENSOR AUTHENTICATION : CONFIRMED"
            );

            Serial.println(
                "[S3] SENSOR TRANSACTION : PASS"
            );

            return true;
        }
    }


    Serial.printf(
        "[S3] SENSOR ACK TIMEOUT : %s\n",
        policyName(expectedMode)
    );


    return false;
}


/* ============================================================
 * RECEIVE KEM ACK
 * ============================================================
 */

bool receiveKEMACK(
    uint32_t timeoutMs
)
{
    uint32_t start =
        millis();


    while(
        millis() - start <
        timeoutMs
    )
    {
        serviceTelemetryDuringWait();

        int packetSize =
            udp.parsePacket();


        if(
            packetSize <= 0
        )
        {
            delay(5);

            continue;
        }


        if(
            packetSize != 4
        )
        {
            uint8_t discard[1024];

            while(
                udp.available()
            )
            {
                udp.read(
                    discard,
                    sizeof(discard)
                );
            }

            continue;
        }


        uint8_t packet[4];


        if(
            udp.read(
                packet,
                4
            ) != 4
        )
        {
            continue;
        }


        if(
            packet[0] == 'A' &&
            packet[1] == 'I' &&
            packet[2] == PACKET_KEM_ACK &&
            packet[3] == SECURITY_MLKEM512
        )
        {
            Serial.println(
                "[S3] KEM ACK RECEIVED : PASS"
            );

            Serial.println(
                "[S3] NODE CONFIRMED ML-KEM VERIFY FAIL = 0"
            );

            return true;
        }
    }


    Serial.println(
        "[S3] KEM ACK TIMEOUT"
    );


    return false;
}


/* ============================================================
 * GENERATE AES-GCM NONCE
 * ============================================================
 */

void generateNonce()
{
    for(
        int i = 0;
        i < GCM_NONCE_SIZE;
        i++
    )
    {
        nonce[i] =
            (uint8_t)(
                esp_random() & 0xFF
            );
    }
}


/* ============================================================
 * AES-GCM ENCRYPT
 *
 * Encrypts the latest REAL sensorData.
 * ============================================================
 */

bool aesEncrypt(
    const uint8_t* key,
    size_t keyBits
)
{
    generateNonce();


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
            "[S3] GCM SETKEY FAILED : %d\n",
            ret
        );


        mbedtls_gcm_free(
            &ctx
        );


        return false;
    }


    ret =
        mbedtls_gcm_crypt_and_tag(
            &ctx,

            MBEDTLS_GCM_ENCRYPT,

            sizeof(SensorPacket),

            nonce,

            GCM_NONCE_SIZE,

            nullptr,

            0,

            (const unsigned char*)
            &sensorData,

            encryptedSensor,

            GCM_TAG_SIZE,

            tag
        );


    mbedtls_gcm_free(
        &ctx
    );


    if(
        ret != 0
    )
    {
        Serial.printf(
            "[S3] AES-GCM FAILED : %d\n",
            ret
        );

        return false;
    }


    return true;
}


/* ============================================================
 * SEND ENCRYPTED SENSOR PACKET
 *
 * waitForACK = true
 *     Used during security transition.
 *
 * waitForACK = false
 *     Used during continuous operation.
 *
 * IMPORTANT:
 *
 * ML-KEM is NOT performed here.
 *
 * In CRITICAL mode the already-established
 * ML-KEM shared secret is used as the AES-256-GCM key.
 *
 * ============================================================
 */

bool sendEncryptedSensorPacket(
    uint8_t mode,
    bool waitForACK
)
{
    if(
        !haveSensorData
    )
    {
        return false;
    }


    const uint8_t* key = nullptr;

    size_t keyBits = 0;


    if(
        mode == SECURITY_NORMAL
    )
    {
        key =
            AES128_KEY;

        keyBits =
            128;
    }


    else if(
        mode == SECURITY_ELEVATED
    )
    {
        key =
            AES256_KEY;

        keyBits =
            256;
    }


    else if(
        mode == SECURITY_CRITICAL
    )
    {
        if(
            !kemSuccess
        )
        {
            Serial.println(
                "[S3] CRITICAL ENCRYPTION BLOCKED: KEM NOT READY"
            );

            return false;
        }


        key =
            sharedSecret;

        keyBits =
            256;
    }


    else
    {
        return false;
    }


    /*
     * Encrypt latest real SensorPacket.
     */

    if(
        !aesEncrypt(
            key,
            keyBits
        )
    )
    {
        Serial.println(
            "[S3] SENSOR ENCRYPTION : FAIL"
        );

        return false;
    }


    /*
     * Build:
     *
     * A I MODE
     * + NONCE
     * + CIPHERTEXT
     * + TAG
     *
     * TOTAL = 44 BYTES
     */

    uint8_t packet[
        4 +
        GCM_NONCE_SIZE +
        sizeof(SensorPacket) +
        GCM_TAG_SIZE
    ];


    packet[0] =
        'A';

    packet[1] =
        'I';

    packet[2] =
        PACKET_SENSOR;

    packet[3] =
        mode;


    memcpy(
        packet + 4,
        nonce,
        GCM_NONCE_SIZE
    );


    memcpy(
        packet +
        4 +
        GCM_NONCE_SIZE,

        encryptedSensor,

        sizeof(SensorPacket)
    );


    memcpy(
        packet +
        4 +
        GCM_NONCE_SIZE +
        sizeof(SensorPacket),

        tag,

        GCM_TAG_SIZE
    );


    if(
        udp.beginPacket(
            NODE_IP,
            NODE_PORT
        ) != 1
    )
    {
        Serial.println(
            "[S3] SENSOR PACKET START FAILED"
        );

        return false;
    }


    size_t written =
        udp.write(
            packet,
            sizeof(packet)
        );


    int result =
        udp.endPacket();


    if(
        written != sizeof(packet) ||
        result != 1
    )
    {
        Serial.println(
            "[S3] SENSOR PACKET TRANSMISSION : FAIL"
        );

        return false;
    }


    /*
     * Continuous transmission path.
     */

    if(
        !waitForACK
    )
    {
        Serial.printf(
            "[S3] ENCRYPTED SENSOR : %s | SEQ=%lu | MQ132=%d\n",
            securityProfile(mode),
            (unsigned long)sensorData.sequence,
            sensorData.mq132
        );

        return true;
    }


    /*
     * Transition verification path.
     */

    Serial.printf(
        "[S3] SENSOR PACKET SENT : %s\n",
        securityProfile(mode)
    );


    Serial.printf(
        "[S3] SENSOR SEQUENCE : %lu\n",
        (unsigned long)sensorData.sequence
    );


    return receiveSensorACK(
        mode,
        5000
    );
}


/* ============================================================
 * RECEIVE NODE PUBLIC KEY
 *
 * 4 + 800 = 804 BYTES
 * ============================================================
 */

bool receivePublicKey(
    uint32_t timeoutMs
)
{
    uint32_t start =
        millis();


    while(
        millis() - start <
        timeoutMs
    )
    {
        int size =
            udp.parsePacket();


        if(
            size <= 0
        )
        {
            delay(5);

            continue;
        }


        if(
            size !=
            4 + PK_SIZE
        )
        {
            uint8_t discard[1024];

            while(
                udp.available()
            )
            {
                udp.read(
                    discard,
                    sizeof(discard)
                );
            }

            continue;
        }


        uint8_t packet[
            4 + PK_SIZE
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
            continue;
        }


        if(
            packet[0] != 'A' ||
            packet[1] != 'I' ||
            packet[2] != PACKET_KEM_KEY ||
            packet[3] != SECURITY_MLKEM512
        )
        {
            continue;
        }


        memcpy(
            publicKey,
            packet + 4,
            PK_SIZE
        );


        Serial.println(
            "[S3] PUBLIC KEY RECEIVED : PASS"
        );


        printHex(
            "PK : ",
            publicKey,
            32
        );


        pkReceived =
            true;


        return true;
    }


    Serial.println(
        "[S3] PUBLIC KEY TIMEOUT"
    );


    return false;
}


/* ============================================================
 * ML-KEM ENCAPSULATION TASK
 *
 * Dedicated 64 KB task.
 *
 * This preserves the stack fix from the working system.
 * ============================================================
 */

void kemTask(
    void* parameter
)
{
    Serial.println();

    Serial.println(
        "[S3 KEM TASK] ONLINE"
    );

    Serial.println(
        "[S3 KEM TASK] Stack : 65536 bytes"
    );


    uint32_t start =
        micros();


    int ret =
        PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc(
            ciphertext,
            sharedSecret,
            publicKey
        );


    uint32_t elapsed =
        micros() - start;


    Serial.printf(
        "ML-KEM return : %d\n",
        ret
    );


    Serial.printf(
        "Encapsulation time : %lu us\n",
        (unsigned long)elapsed
    );


    if(
        ret != 0
    )
    {
        Serial.println(
            "ML-KEM ENCAPSULATION : FAIL"
        );

        kemSuccess =
            false;

        kemFinished =
            true;

        vTaskDelete(
            NULL
        );

        return;
    }


    Serial.println(
        "ML-KEM ENCAPSULATION : PASS"
    );


    printHex(
        "SHARED SECRET : ",
        sharedSecret,
        SS_SIZE
    );


    printHex(
        "CIPHERTEXT : ",
        ciphertext,
        32
    );


    kemSuccess =
        true;

    kemFinished =
        true;


    Serial.println(
        "[S3 KEM TASK] FINISHED"
    );


    vTaskDelete(
        NULL
    );
}


/* ============================================================
 * START KEM TASK
 * ============================================================
 */

bool startKEMTask()
{
    kemFinished =
        false;

    kemSuccess =
        false;


    BaseType_t result =
        xTaskCreate(
            kemTask,
            "S3_KEM_Enc",
            65536,
            nullptr,
            1,
            nullptr
        );


    if(
        result != pdPASS
    )
    {
        Serial.println(
            "[S3] KEM TASK CREATION : FAIL"
        );

        return false;
    }


    Serial.println(
        "[S3] KEM TASK CREATED : PASS"
    );


    return true;
}


/* ============================================================
 * LIVE EDGE-AI FEATURE EXTRACTION
 * ============================================================
 */

#define FEATURE_COUNT  12
#define FEATURE_WINDOW 100


static double mlFeatures[
    FEATURE_COUNT
];


static double mlOutput[2];


static float rssiSamples[
    FEATURE_WINDOW
];


static float iatSamples[
    FEATURE_WINDOW - 1
];


static uint32_t seqSamples[
    FEATURE_WINDOW
];


static uint32_t featureCount =
    0;



static uint32_t invalidFeaturePackets =
    0;


static uint32_t featureWindowStart =
    0;


static uint32_t previousArrival =
    0;


static bool haveArrival =
    false;


/* ============================================================
 * BACKGROUND TELEMETRY SERVICE
 *
 * IMPORTANT:
 * During policy/KEM ACK waits, telemetry must continue to be
 * drained from UDP 5008. This function deliberately does NOT
 * run TinyML and does NOT trigger a policy transition.
 * It only keeps the latest real sensor packet updated and
 * prevents the telemetry UDP receive queue from overflowing.
 * ============================================================
 */
static void serviceTelemetryDuringWait()
{
    int telemetrySize = telemetryUdp.parsePacket();

    if(telemetrySize <= 0)
        return;

    if(telemetrySize != (int)sizeof(SensorPacket))
    {
        uint8_t discard[1024];
        while(telemetryUdp.available())
            telemetryUdp.read(discard, sizeof(discard));
        return;
    }

    uint8_t b[sizeof(SensorPacket)];

    if(telemetryUdp.read(b, sizeof(b)) != sizeof(b))
        return;

    SensorPacket p;
    memcpy(&p, b, sizeof(p));

    /* Always keep the latest REAL sensor data current. */
    sensorData = p;
    haveSensorData = true;

    /*
     * Keep collecting the next ML window while the control
     * channel is waiting. Do NOT call runLiveInference() here.
     */
    if(featureCount >= FEATURE_WINDOW)
    {
        pendingMLInference = true;
        return;
    }

    uint32_t now = millis();

    if(featureCount == 0)
        featureWindowStart = now;

    if(haveArrival && featureCount > 0)
    {
        iatSamples[featureCount - 1] =
            (float)(now - previousArrival);
    }

    rssiSamples[featureCount] = (float)p.rssi;
    seqSamples[featureCount] = p.sequence;
    featureCount++;

    if(featureCount >= FEATURE_WINDOW)
        pendingMLInference = true;

    previousArrival = now;
    haveArrival = true;
}


/* ============================================================
 * FEATURE HELPERS
 * ============================================================
 */

static float fmean(
    const float* a,
    uint32_t n
)
{
    if(
        !n
    )
    {
        return 0.0f;
    }


    double s =
        0;


    for(
        uint32_t i = 0;
        i < n;
        i++
    )
    {
        s += a[i];
    }


    return (float)(
        s / n
    );
}


static float fvar(
    const float* a,
    uint32_t n,
    float m
)
{
    if(
        n <= 1
    )
    {
        return 0.0f;
    }


    double s =
        0;


    for(
        uint32_t i = 0;
        i < n;
        i++
    )
    {
        double d =
            a[i] - m;

        s +=
            d * d;
    }


    return (float)(
        s / n
    );
}


static float fminv(
    const float* a,
    uint32_t n
)
{
    if(
        !n
    )
    {
        return 0;
    }


    float v =
        a[0];


    for(
        uint32_t i = 1;
        i < n;
        i++
    )
    {
        if(
            a[i] < v
        )
        {
            v =
                a[i];
        }
    }


    return v;
}


static float fmaxv(
    const float* a,
    uint32_t n
)
{
    if(
        !n
    )
    {
        return 0;
    }


    float v =
        a[0];


    for(
        uint32_t i = 1;
        i < n;
        i++
    )
    {
        if(
            a[i] > v
        )
        {
            v =
                a[i];
        }
    }


    return v;
}


/* ============================================================
 * RESET ML WINDOW
 * ============================================================
 */

static void resetMLWindow()
{
    featureCount =
        0;

    invalidFeaturePackets =
        0;

    haveArrival =
        false;

    previousArrival =
        0;

    featureWindowStart =
        millis();
}


/* ============================================================
 * BUILD ML FEATURES
 *
 * EXACT MODEL ORDER:
 *
 * 0  rssi_mean
 * 1  rssi_variance
 * 2  rssi_min
 * 3  rssi_max
 * 4  rssi_range
 * 5  packet_loss
 * 6  iat_mean
 * 7  iat_variance
 * 8  iat_min
 * 9  iat_max
 * 10 packet_rate
 * 11 invalid_packets
 *
 * ============================================================
 */

static void buildMLFeatures()
{
    uint32_t n =
        featureCount;


    uint32_t in =
        n > 1
        ? n - 1
        : 0;


    float rm =
        fmean(
            rssiSamples,
            n
        );


    float rv =
        fvar(
            rssiSamples,
            n,
            rm
        );


    float rmin =
        fminv(
            rssiSamples,
            n
        );


    float rmax =
        fmaxv(
            rssiSamples,
            n
        );


    float im =
        fmean(
            iatSamples,
            in
        );


    float iv =
        fvar(
            iatSamples,
            in,
            im
        );


    float imin =
        fminv(
            iatSamples,
            in
        );


    float imax =
        fmaxv(
            iatSamples,
            in
        );


    uint32_t expected =
        0;


    if(
        n > 1
    )
    {
        expected =
            seqSamples[n - 1]
            -
            seqSamples[0]
            +
            1;
    }
    else if(
        n == 1
    )
    {
        expected =
            1;
    }


    float loss =
        0;


    if(
        expected >= n &&
        expected > 0
    )
    {
        loss =
            (float)(
                expected - n
            )
            /
            (float)expected;
    }


    float elapsed =
        (
            millis()
            -
            featureWindowStart
        )
        /
        1000.0f;


    float rate =
        elapsed > 0
        ?
        (float)n / elapsed
        :
        0;


    mlFeatures[0] =
        rm;

    mlFeatures[1] =
        rv;

    mlFeatures[2] =
        rmin;

    mlFeatures[3] =
        rmax;

    mlFeatures[4] =
        rmax - rmin;

    mlFeatures[5] =
        loss;

    mlFeatures[6] =
        im;

    mlFeatures[7] =
        iv;

    mlFeatures[8] =
        imin;

    mlFeatures[9] =
        imax;

    mlFeatures[10] =
        rate;

    mlFeatures[11] =
        (double)
        invalidFeaturePackets;
}


/* ============================================================
 * THREAT -> SECURITY POLICY
 * ============================================================
 */

static uint8_t threatLevelToSecurityPolicy(
    int threatLevel
)
{
    switch(
        threatLevel
    )
    {
        case THREAT_NORMAL:
            return SECURITY_NORMAL;

        case THREAT_ELEVATED:
            return SECURITY_ELEVATED;

        case THREAT_CRITICAL:
            return SECURITY_CRITICAL;

        default:
            return SECURITY_NORMAL;
    }
}


/* ============================================================
 * THREAT NAME
 * ============================================================
 */

static const char* threatLevelName(
    int threatLevel
)
{
    switch(
        threatLevel
    )
    {
        case THREAT_NORMAL:
            return "NORMAL";

        case THREAT_ELEVATED:
            return "ELEVATED";

        case THREAT_CRITICAL:
            return "CRITICAL";

        default:
            return "UNKNOWN";
    }
}


/* ============================================================
 * CRITICAL SECURITY
 *
 * Performs ML-KEM key establishment ONCE when entering
 * CRITICAL mode.
 *
 * After this function succeeds:
 *
 * sharedSecret
 *      |
 *      v
 * AES-256-GCM
 *      |
 *      v
 * continuous sensor encryption
 *
 * ============================================================
 */

static bool activateCriticalSecurity()
{
    Serial.println();

    Serial.println(
        "************************************************"
    );

    Serial.println(
        "       CRITICAL SECURITY ACTIVATION"
    );

    Serial.println(
        "************************************************"
    );


    Serial.printf(
        "[S3] SENSOR SNAPSHOT : SEQ=%lu RSSI=%d MQ132=%d\n",
        (unsigned long)sensorData.sequence,
        sensorData.rssi,
        sensorData.mq132
    );


    /*
     * Synchronize policy with Node.
     */

    if(
        !sendPolicyAndWait(
            SECURITY_CRITICAL
        )
    )
    {
        return false;
    }


    /*
     * Reset KEM state.
     */

    pkReceived =
        false;

    kemFinished =
        false;

    kemSuccess =
        false;


    /*
     * Receive fresh Node public key.
     */

    if(
        !receivePublicKey(
            10000
        )
    )
    {
        Serial.println(
            "[S3] CRITICAL PUBLIC KEY : FAIL"
        );

        return false;
    }


    /*
     * Start dedicated ML-KEM task.
     */

    if(
        !startKEMTask()
    )
    {
        return false;
    }


    /*
     * Wait for encapsulation.
     */

    uint32_t waitStart =
        millis();


    while(
        !kemFinished &&
        millis() - waitStart <
        15000
    )
    {
        serviceTelemetryDuringWait();
        delay(2);
    }


    if(
        !kemSuccess
    )
    {
        Serial.println(
            "[S3] ML-KEM ENCAPSULATION : FAIL"
        );

        return false;
    }


    /*
     * Send ciphertext to Node.
     */

    uint8_t packet[
        4 + CT_SIZE
    ];


    packet[0] =
        'A';

    packet[1] =
        'I';

    packet[2] =
        PACKET_KEM_CT;

    packet[3] =
        SECURITY_MLKEM512;


    memcpy(
        packet + 4,
        ciphertext,
        CT_SIZE
    );


    if(
        udp.beginPacket(
            NODE_IP,
            NODE_PORT
        ) != 1
    )
    {
        Serial.println(
            "[S3] KEM CIPHERTEXT START FAILED"
        );

        return false;
    }


    if(
        udp.write(
            packet,
            sizeof(packet)
        )
        !=
        sizeof(packet)
    )
    {
        Serial.println(
            "[S3] KEM CIPHERTEXT WRITE FAILED"
        );

        return false;
    }


    if(
        udp.endPacket()
        !=
        1
    )
    {
        Serial.println(
            "[S3] KEM CIPHERTEXT SEND FAILED"
        );

        return false;
    }


    Serial.println(
        "[S3] KEM CIPHERTEXT SENT : PASS"
    );


    /*
     * Wait for Node's verified KEM ACK.
     */

    if(
        !receiveKEMACK(
            10000
        )
    )
    {
        return false;
    }


    Serial.println(
        "[S3] ML-KEM HANDSHAKE : PASS"
    );


    /*
     * Send first encrypted CRITICAL sensor packet.
     *
     * This one waits for ACK so that the transition is
     * explicitly verified.
     */

    if(
        !sendEncryptedSensorPacket(
            SECURITY_CRITICAL,
            true
        )
    )
    {
        return false;
    }


    Serial.println(
        "[S3] CRITICAL SECURITY : ACTIVE"
    );


    Serial.println(
        "[S3] ML-KEM established."
    );


    Serial.println(
        "[S3] Continuous AES-256-GCM sensor encryption : ACTIVE"
    );


    return true;
}


/* ============================================================
 * DEDICATED XGBOOST INFERENCE TASK
 *
 * IMPORTANT:
 * The generated 4-class XGBoost model is large and uses many
 * local double variables. Running score() from loopTask can
 * overflow the loopTask stack on ESP32-S3.
 *
 * Keep the proven crypto code unchanged. Only the ML inference
 * call is isolated in its own large-stack FreeRTOS task.
 * ============================================================
 */

static void mlInferenceTask(void *parameter)
{
    (void)parameter;

    uint32_t start = micros();

    score(
        mlFeatures,
        mlOutput
    );

    mlInferenceElapsedUs =
        micros() - start;

    mlInferenceTaskOK = true;
    mlInferenceFinished = true;

    Serial.println(
        "[S3] XGBOOST TASK : FINISHED"
    );

    vTaskDelete(
        NULL
    );
}


/* ============================================================
 * RUN LIVE INFERENCE
 *
 * Feature extraction and all adaptive-security logic remain in
 * the existing loop context. Only the generated XGBoost score()
 * execution is moved to a dedicated FreeRTOS task.
 * ============================================================
 */

static void runLiveInference()
{
    pendingMLInference = false;

    // ========================================================
    // BUILD ML FEATURES
    // ========================================================

    buildMLFeatures();

    // ========================================================
    // DEBUG: PRINT COMPLETE ML FEATURE VECTOR
    // ========================================================

    Serial.println();
    Serial.println("================================================");
    Serial.println("           ML FEATURE VECTOR");
    Serial.println("================================================");

    Serial.printf(
        "Feature  0 | rssi_mean       = %.6f\n",
        mlFeatures[0]
    );

    Serial.printf(
        "Feature  1 | rssi_variance   = %.6f\n",
        mlFeatures[1]
    );

    Serial.printf(
        "Feature  2 | rssi_min        = %.6f\n",
        mlFeatures[2]
    );

    Serial.printf(
        "Feature  3 | rssi_max        = %.6f\n",
        mlFeatures[3]
    );

    Serial.printf(
        "Feature  4 | rssi_range      = %.6f\n",
        mlFeatures[4]
    );

    Serial.printf(
        "Feature  5 | packet_loss     = %.6f\n",
        mlFeatures[5]
    );

    Serial.printf(
        "Feature  6 | iat_mean        = %.6f\n",
        mlFeatures[6]
    );

    Serial.printf(
        "Feature  7 | iat_variance    = %.6f\n",
        mlFeatures[7]
    );

    Serial.printf(
        "Feature  8 | iat_min         = %.6f\n",
        mlFeatures[8]
    );

    Serial.printf(
        "Feature  9 | iat_max         = %.6f\n",
        mlFeatures[9]
    );

    Serial.printf(
        "Feature 10 | packet_rate     = %.6f\n",
        mlFeatures[10]
    );

    Serial.printf(
        "Feature 11 | invalid_packets = %.6f\n",
        mlFeatures[11]
    );

    Serial.println("================================================");

    // ========================================================
    // XGBOOST INFERENCE -- DEDICATED FREE RTOS TASK
    // ========================================================

    mlInferenceFinished = false;
    mlInferenceTaskOK = false;
    mlInferenceElapsedUs = 0;

    BaseType_t taskResult =
        xTaskCreate(
            mlInferenceTask,
            "S3_ML_Infer",
            65536,
            nullptr,
            1,
            nullptr
        );

    if(
        taskResult != pdPASS
    )
    {
        Serial.println(
            "[S3] XGBOOST TASK CREATION : FAIL"
        );

        pendingMLInference = false;
        return;
    }

    Serial.println(
        "[S3] XGBOOST TASK CREATED : PASS"
    );

    uint32_t mlWaitStart = millis();

    while(
        !mlInferenceFinished &&
        millis() - mlWaitStart < 10000
    )
    {
        /* Keep the main system responsive while the dedicated
         * ML task performs the generated XGBoost inference. */
        serviceTelemetryDuringWait();
        delay(2);
    }

    if(
        !mlInferenceFinished ||
        !mlInferenceTaskOK
    )
    {
        Serial.println(
            "[S3] XGBOOST INFERENCE : TIMEOUT/FAIL"
        );

        pendingMLInference = false;
        return;
    }

    uint32_t elapsed =
        mlInferenceElapsedUs;

    double pNormal =
        mlOutput[0];

    double pAttack =
        mlOutput[1];

    // Safety clamp
    if(pNormal < 0)
        pNormal = 0;

    if(pNormal > 1)
        pNormal = 1;

    if(pAttack < 0)
        pAttack = 0;

    if(pAttack > 1)
        pAttack = 1;

    // ========================================================
    // THREAT LEVEL
    // ========================================================

    int threatLevel =
        getThreatLevel(
            (float)pAttack
        );

    uint8_t newPolicy =
        threatLevelToSecurityPolicy(
            threatLevel
        );

    // ========================================================
    // PRINT ML RESULT
    // ========================================================

    Serial.println();
    Serial.println("================================================");
    Serial.println("        EDGE-AI XGBOOST INFERENCE");
    Serial.println("================================================");

    Serial.printf(
        "P(NORMAL)      : %.9f\n",
        pNormal
    );

    Serial.printf(
        "P(ATTACK)      : %.9f\n",
        pAttack
    );

    Serial.printf(
        "Inference time : %lu us\n",
        (unsigned long)elapsed
    );

    Serial.printf(
        "Threat level   : %d (%s)\n",
        threatLevel,
        threatLevelName(threatLevel)
    );

    Serial.printf(
        "Security mode  : %u (%s)\n",
        newPolicy,
        policyName(newPolicy)
    );

    Serial.printf(
        "Crypto profile : %s\n",
        securityProfile(newPolicy)
    );

    Serial.println("================================================");

    // ========================================================
    // IMPORTANT: start collecting the NEXT ML window BEFORE
    // any policy/ACK/KEM operation that may take time.
    // This prevents the telemetry stream from being frozen
    // during security synchronization.
    // ========================================================
    resetMLWindow();

    // ========================================================
    // ADAPTIVE SECURITY TRANSITION
    // ========================================================

    if(
        newPolicy != currentSecurityPolicy
    )
    {
        Serial.println(
            "******** ADAPTIVE SECURITY TRANSITION ********"
        );

        Serial.printf(
            "OLD POLICY     : %u (%s)\n",
            currentSecurityPolicy,
            policyName(currentSecurityPolicy)
        );

        Serial.printf(
            "NEW THREAT     : %d (%s)\n",
            threatLevel,
            threatLevelName(threatLevel)
        );

        Serial.printf(
            "NEW POLICY     : %u (%s)\n",
            newPolicy,
            policyName(newPolicy)
        );

        Serial.printf(
            "ACTION         : %s\n",
            securityProfile(newPolicy)
        );

        Serial.println(
            "***********************************************"
        );

        bool success = false;

        // ----------------------------------------------------
        // NORMAL / ELEVATED
        // ----------------------------------------------------

        if(
            newPolicy == SECURITY_NORMAL ||
            newPolicy == SECURITY_ELEVATED
        )
        {
            if(
                sendPolicyAndWait(
                    newPolicy
                )
            )
            {
                success =
                    sendEncryptedSensorPacket(
                        newPolicy,
                        true
                    );
            }
        }

        // ----------------------------------------------------
        // CRITICAL
        // ----------------------------------------------------

        else if(
            newPolicy == SECURITY_CRITICAL
        )
        {
            success =
                activateCriticalSecurity();
        }

        // ----------------------------------------------------
        // UPDATE ACTIVE POLICY
        // ----------------------------------------------------

        if(success)
        {
            currentSecurityPolicy =
                newPolicy;

            currentThreatLevel =
                threatLevel;

            Serial.printf(
                "[S3] ADAPTIVE POLICY ACTIVE : %s\n",
                securityProfile(
                    newPolicy
                )
            );
        }
        else
        {
            Serial.println(
                "[S3] ADAPTIVE TRANSITION : FAIL"
            );
        }
    }

    // ========================================================
    // NO POLICY CHANGE
    // ========================================================

    else
    {
        currentThreatLevel =
            threatLevel;

        Serial.printf(
            "[S3] POLICY UNCHANGED : %s\n",
            securityProfile(
                currentSecurityPolicy
            )
        );
    }

    Serial.println(
        "================================================"
    );
}

/* ============================================================
 * PROCESS LIVE SENSOR
 *
 * Linux relay -> S3
 *
 * The latest real packet becomes the data source for
 * continuous encryption.
 * ============================================================
 */

static void processLiveSensor(
    const uint8_t* data,
    int len
)
{
    if(
        len !=
        (int)sizeof(SensorPacket)
    )
    {
        invalidFeaturePackets++;

        return;
    }


    SensorPacket p;


    memcpy(
        &p,
        data,
        sizeof(p)
    );


    uint32_t now =
        millis();


    if(
        featureCount == 0
    )
    {
        featureWindowStart =
            now;
    }


    if(
        haveArrival &&
        featureCount <
        FEATURE_WINDOW
    )
    {
        iatSamples[
            featureCount - 1
        ] =
            (float)(
                now -
                previousArrival
            );
    }


    if(
        featureCount >=
        FEATURE_WINDOW
    )
    {
        /* Keep the latest REAL sensor data even if the ML window
         * is temporarily full. The main loop will process the
         * completed window on its normal path. */
        sensorData = p;
        haveSensorData = true;
        return;
    }


    rssiSamples[
        featureCount
    ] =
        (float)p.rssi;


    seqSamples[
        featureCount
    ] =
        p.sequence;


    featureCount++;


    previousArrival =
        now;


    haveArrival =
        true;


    /*
     * IMPORTANT:
     *
     * This is the latest REAL sensor data.
     *
     * Continuous encryption always uses this value.
     */

    sensorData =
        p;


    haveSensorData =
        true;


    Serial.printf(
        "[S3] OBS SEQ=%lu RSSI=%d MQ132=%d\n",
        (unsigned long)p.sequence,
        p.rssi,
        p.mq132
    );


    /*
     * Run TinyML after 100 packets.
     */

    if(
        featureCount >=
        FEATURE_WINDOW
    )
    {
        runLiveInference();
    }
}


/* ============================================================
 * DRAIN OLD SENSOR ACKS
 *
 * During continuous operation the Node continues sending
 * sensor ACKs.
 *
 * We do not block waiting for each ACK, but we periodically
 * remove the ACK packets from the control socket so that
 * the UDP receive queue does not fill.
 *
 * ============================================================
 */

static void drainContinuousACKs()
{
    while(
        true
    )
    {
        serviceTelemetryDuringWait();

        int packetSize =
            udp.parsePacket();


        if(
            packetSize <= 0
        )
        {
            break;
        }


        if(
            packetSize != 4
        )
        {
            uint8_t discard[1024];

            while(
                udp.available()
            )
            {
                udp.read(
                    discard,
                    sizeof(discard)
                );
            }

            continue;
        }


        uint8_t packet[4];


        if(
            udp.read(
                packet,
                4
            )
            !=
            4
        )
        {
            continue;
        }


        if(
            packet[0] == 'A' &&
            packet[1] == 'I'
        )
        {
            if(
                packet[2] ==
                PACKET_SENSOR_ACK
            )
            {
                /*
                 * Sensor ACK received during continuous mode.
                 *
                 * Authentication was already performed by Node.
                 */

                continue;
            }


            /*
             * Other 4-byte packets are simply ignored here.
             *
             * Transition functions consume their own ACKs.
             */
        }
    }
}


/* ============================================================
 * SETUP
 * ============================================================
 */

void setup()
{
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
        "   ESP32-S3 EDGE-AI SECURITY HUB"
    );


    Serial.println(
        "   BUILD: FINAL-ADAPTIVE-SECURITY-HUB"
    );


    Serial.println(
        "################################################"
    );


    connectWiFi();


    if(
        !startUDP()
    )
    {
        while(
            true
        )
        {
            delay(1000);
        }
    }


    resetMLWindow();


    Serial.println();


    Serial.println(
        "[S3] Model : adaptive_threat_xgb.h"
    );


    Serial.println(
        "[S3] Feature count : 12"
    );


    Serial.println(
        "[S3] ML window : 100 packets"
    );


    Serial.println();


    Serial.println(
        "[S3] NORMAL   -> AES-128-GCM"
    );


    Serial.println(
        "[S3] ELEVATED -> AES-256-GCM"
    );


    Serial.println(
        "[S3] CRITICAL -> ML-KEM-512 + AES-256-GCM"
    );


    Serial.println();


    Serial.printf(
        "[S3] Continuous encryption interval : %lu ms\n",
        (unsigned long)
        ENCRYPTED_SENSOR_INTERVAL_MS
    );


    Serial.println();


    Serial.println(
        "################################################"
    );


    Serial.println(
        "S3 HUB READY"
    );


    Serial.println(
        "Linux telemetry -> Edge-AI : ACTIVE"
    );


    Serial.println(
        "TinyML threat detection   : ACTIVE"
    );


    Serial.println(
        "Adaptive security policy  : ACTIVE"
    );


    Serial.println(
        "Continuous encryption     : ARMED"
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
     * 1. RECEIVE TELEMETRY
     *
     * Linux relay -> S3
     * UDP 5008
     * ========================================================
     */

    int telemetrySize =
        telemetryUdp.parsePacket();


    if(
        telemetrySize > 0
    )
    {
        if(
            telemetrySize ==
            (int)sizeof(SensorPacket)
        )
        {
            uint8_t b[
                sizeof(SensorPacket)
            ];


            if(
                telemetryUdp.read(
                    b,
                    sizeof(b)
                )
                ==
                sizeof(b)
            )
            {
                processLiveSensor(
                    b,
                    sizeof(b)
                );
            }
        }
        else
        {
            uint8_t discard[1024];


            while(
                telemetryUdp.available()
            )
            {
                telemetryUdp.read(
                    discard,
                    sizeof(discard)
                );
            }


            invalidFeaturePackets++;
        }
    }


    /* ========================================================
     * 2. PROCESS A ML WINDOW THAT FINISHED DURING A SECURITY
     *    TRANSITION. This runs outside the blocking transition
     *    path, so telemetry reception remains responsive.
     * ========================================================
     */

    if(pendingMLInference && featureCount >= FEATURE_WINDOW)
    {
        runLiveInference();
        resetMLWindow();
    }


    /* ========================================================
     * 3. CONTINUOUS ENCRYPTED SENSOR TRANSMISSION
     *
     * Once a policy is active:
     *
     * NORMAL:
     *     AES-128-GCM
     *
     * ELEVATED:
     *     AES-256-GCM
     *
     * CRITICAL:
     *     ML-KEM-derived AES-256-GCM
     *
     * ========================================================
     */

    if(
        currentSecurityPolicy >=
        SECURITY_NORMAL
    )
    {
        if(
            haveSensorData &&
            millis() -
            lastEncryptedSensorMs >=
            ENCRYPTED_SENSOR_INTERVAL_MS
        )
        {
            lastEncryptedSensorMs =
                millis();


            sendEncryptedSensorPacket(
                currentSecurityPolicy,
                false
            );
        }
    }


    /* ========================================================
     * 4. DRAIN CONTINUOUS SENSOR ACKS
     *
     * Does not block the system.
     * ========================================================
     */

    if(
        currentSecurityPolicy >=
        SECURITY_NORMAL
    )
    {
        drainContinuousACKs();
    }


    /* ========================================================
     * 5. SMALL LOOP DELAY
     * ========================================================
     */

    delay(2);
}