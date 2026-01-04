#ifndef CCB_CONTACT_H
#define CCB_CONTACT_H

#include "uint256.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/sha.h>
#include <stdint.h>

// contact struct, serialization

typedef struct {
    kad_uint256_t id;
    char host[INET6_ADDRSTRLEN];
    int port;
} kad_contact_t;

/*
    compact format (inside bencoded messages):
      - ipv4: 26 bytes (20 id + 4 ip + 2 port)
      - ipv6: 38 bytes (20 id + 16 ip + 2 port)
*/

int kad_contact_to_compact(const kad_contact_t *contact, uint8_t *buf, size_t len);
int kad_contact_from_compact(kad_contact_t *contact, const uint8_t *buf, size_t len);
int kad_contact_compact_size(const kad_contact_t *contact);

// helpers for batch operations (find_node, get_peers)
int kad_contacts_to_compact(const kad_contact_t *contacts, size_t count, uint8_t *buf, size_t len);
int kad_contacts_from_compact(
    kad_contact_t *contacts, size_t max_count, const uint8_t *buf, size_t len);

/*
    bencode format (for standalone contact encoding):
    d2:id20:<node_id>:4:host<len>:<ip>4:porti<port>ee

    https://en.wikipedia.org/wiki/Bencode#Encoding_Algorithm
*/

int kad_contact_bencode(const kad_contact_t *contact, uint8_t *buf, size_t len);
int kad_contact_bdecode(kad_contact_t *contact, const uint8_t *buf, size_t len, size_t *consumed);

#endif