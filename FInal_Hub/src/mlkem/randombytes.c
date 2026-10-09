#include "randombytes.h"
#include "esp_random.h"

// Custom ESP32 Hardware RNG Wrapper (Now with the PQClean prefix!)
int PQCLEAN_randombytes(uint8_t *buf, size_t n) {
    esp_fill_random(buf, n);
    return 0;
}