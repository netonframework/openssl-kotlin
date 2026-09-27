#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <stdint.h>
#include "neton_crypto.h"

static uint64_t now(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t)) abort();
    return (uint64_t)t.tv_sec * 1000000000ULL + (uint64_t)t.tv_nsec;
}
int main(int argc, char **argv) {
    int size = argc > 1 ? atoi(argv[1]) : 1200;
    int iterations = argc > 2 ? atoi(argv[2]) : 100000;
    int algorithm = argc > 3 ? atoi(argv[3]) : 0;
    if (size < 1 || size > 65536 || iterations < 1 || iterations > 10000000 || algorithm < 0 || algorithm > 2) return 2;
    unsigned char key_bytes[32] = {0}, nonce[12] = {0}, aad[16] = {0};
    unsigned char *data = calloc((size_t)size + 16, 1);
    neton_aead *key = neton_aead_new(algorithm, key_bytes);
    uint64_t start = 0, elapsed;
    if (!data || !key) return 3;
    for (int i = 0; i < iterations + 10000; ++i) {
        if (i == 10000) start = now();
        for (int j = 0; j < 4; ++j) nonce[j] = (unsigned char)((unsigned int)i >> (j * 8));
        if (!neton_aead_seal(key, data, size, nonce, aad, 16) || neton_aead_open(key, data, size, nonce, aad, 16) != 1) abort();
    }
    elapsed = now() - start;
    printf("c,%d,%d,%d,%llu,%.6f\n", algorithm, size, iterations, (unsigned long long)elapsed, (double)elapsed / iterations / size / 2.0);
    neton_aead_free(key); free(data); return 0;
}
