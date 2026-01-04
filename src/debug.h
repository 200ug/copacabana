#ifndef CCB_DEBUG_H
#define CCB_DEBUG_H

#include "contact.h"
#include "uint256.h"

void kad_uint256_print(const kad_uint256_t *a, const char *label);
void kad_contact_print(const kad_contact_t *a, const char *label);
void kad_print_hex(const uint8_t *data, size_t len, const char *label);

#endif