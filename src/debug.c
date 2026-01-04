#include "debug.h"
#include <stdio.h>

void kad_uint256_print(const kad_uint256_t *a, const char *label) {
    printf("%s ", label);

    for (int i = 0; i < 8; i++) {
        printf("%08x", a->w[i]);
        if (i < 7) printf(" ");
    }

    printf("\n");
}

void kad_contact_print(const kad_contact_t *c, const char *label) {
    printf("%s\n", label);
    kad_uint256_print(&c->id, "  id:  ");
    printf("  host: %s\n", c->host);
    printf("  port: %d\n", c->port);
}

void kad_print_hex(const uint8_t *data, size_t len, const char *label) {
    printf("%s ", label);

    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
        if ((i + 1) % 4 == 0 && i + 1 < len) printf(" ");
    }

    printf("\n");
}
