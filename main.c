#include "src/contact.h"
#include "src/debug.h"
#include "src/uint256.h"
#include <stdio.h>
#include <string.h>

int main() {
    kad_contact_t a = {0};

    kad_uint256_random(&a.id);
    strcpy(a.host, "192.168.1.1");
    a.port = 6881;

    kad_contact_print(&a, "original");

    uint8_t compact[26];
    int len = kad_contact_to_compact(&a, compact, sizeof(compact));
    kad_print_hex(compact, len, "serialized:");

    kad_contact_t decoded = {0};
    len = kad_contact_from_compact(&decoded, compact, sizeof(compact));
    kad_contact_print(&decoded, "decoded:");

    uint8_t bencode[256];
    len = kad_contact_bencode(&a, bencode, sizeof(bencode));
    printf("serialized (%d bytes): ", len);
    for (int i = 0; i < len; i++) {
        printf("%c", (bencode[i] >= 32 && bencode[i] < 127) ? bencode[i] : '.');
    }
    printf("\n");

    kad_contact_bdecode(&decoded, bencode, len, NULL);
    kad_contact_print(&decoded, "decoded:");

    /* batch examples */

    kad_contact_t contacts[3];
    for (int i = 0; i < 3; i++) {
        kad_uint256_random(&contacts[i].id);
        sprintf(contacts[i].host, "192.168.1.1%d", i + 10);
        contacts[i].port = 6881 + i;
    }

    uint8_t batch[78];
    len = kad_contacts_to_compact(contacts, 3, batch, sizeof(batch));
    printf("encoded 3 contacts to %d bytes\n", len);

    kad_contact_t batch_decoded[3];
    int count = kad_contacts_from_compact(batch_decoded, 3, batch, len);
    printf("decoded %d contacts: ", count);

    int match = 1;
    for (int i = 0; i < 3; i++) {
        if (memcmp(batch_decoded[i].id.w, contacts[i].id.w, 20) != 0) {
            match = 0;
            break;
        }
    }
    printf("%s\n", match ? "all match" : "mismatch");

    return 0;
}
