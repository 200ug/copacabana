#include "uint256.h"
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <stdio.h>

int kad_uint256_cmp(const kad_uint256_t *a, const kad_uint256_t *b) {
    for (int i = 0; i < 8; i++) {
        int cmp = (a->w[i] > b->w[i] - (a->w[i] < b->w[i]));
        if (cmp) return cmp;
    }

    return 0;
}

int kad_uint256_clz(const kad_uint256_t *a) {
    for (int i = 0; i < 8; i++) {
        if (a->w[i] != 0) return (i * 32) + __builtin_clz(a->w[i]);
    }

    return 256; // all zeroes
}

int kad_uint256_is_zero(const kad_uint256_t *a) {
    uint32_t r = 0;

    r |= a->w[0];
    r |= a->w[1];
    r |= a->w[2];
    r |= a->w[3];
    r |= a->w[4];
    r |= a->w[5];
    r |= a->w[6];
    r |= a->w[7];

    return r == 0;
}

void kad_uint256_xor(kad_uint256_t *r, const kad_uint256_t *a, const kad_uint256_t *b) {
    r->w[0] = a->w[0] ^ b->w[0];
    r->w[1] = a->w[1] ^ b->w[1];
    r->w[2] = a->w[2] ^ b->w[2];
    r->w[3] = a->w[3] ^ b->w[3];
    r->w[4] = a->w[4] ^ b->w[4];
    r->w[5] = a->w[5] ^ b->w[5];
    r->w[6] = a->w[6] ^ b->w[6];
    r->w[7] = a->w[7] ^ b->w[7];
}

void kad_uint256_from_bytes(kad_uint256_t *r, const uint8_t bytes[32]) {
    for (int i = 0; i < 8; i++) {
        r->w[i] = ((uint32_t)bytes[i * 4 + 0] << 24) | ((uint32_t)bytes[i * 4 + 1] << 16) |
                  ((uint32_t)bytes[i * 4 + 2] << 8) | ((uint32_t)bytes[i * 4 + 3]);
    }
}

void kad_uint256_from_key(kad_uint256_t *r, const uint8_t *key, const size_t len) {
    uint8_t hash[32];
    SHA256(key, len, hash);
    kad_uint256_from_bytes(r, hash);
}

void kad_uint256_random(kad_uint256_t *r) {
    uint8_t random_data[32];
    RAND_bytes(random_data, 32);
    kad_uint256_from_bytes(r, random_data);
}

void kad_uint256_print(const kad_uint256_t *a, const char *label) {
    printf("%s: ", label);

    for (int i = 0; i < 8; i++) {
        printf("%08x", a->w[i]);
        if (i < 7) printf(" ");
    }

    printf("\n");
}
