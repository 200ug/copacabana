#ifndef CCB_UINT256_H
#define CCB_UINT256_H

#include <openssl/sha.h>
#include <stdint.h>

// id type, xor, comparison

typedef struct {
    uint32_t w[8]; // 256 / 32 (160-bit id + alignment padding)
} kad_uint256_t;

int kad_uint256_cmp(const kad_uint256_t *a, const kad_uint256_t *b);
int kad_uint256_clz(const kad_uint256_t *a); // bucket index calculations
int kad_uint256_is_zero(const kad_uint256_t *a);
void kad_uint256_xor(kad_uint256_t *r, const kad_uint256_t *a, const kad_uint256_t *b);
void kad_uint256_from_bytes(kad_uint256_t *r, const uint8_t bytes[32]);
void kad_uint256_from_key(kad_uint256_t *r, const uint8_t *key, const size_t len);
void kad_uint256_random(kad_uint256_t *r);

#endif
