#include "contact.h"
#include <arpa/inet.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int kad_contact_to_compact(const kad_contact_t *contact, uint8_t *buf, size_t len) {
    if (!contact || !buf) return -1;

    struct in_addr ipv4;
    struct in6_addr ipv6;
    int is_ipv6;

    if (inet_pton(AF_INET, contact->host, &ipv4) == 1) {
        if (len < 26) return -1;
        is_ipv6 = 0;
    } else if (inet_pton(AF_INET6, contact->host, &ipv6) == 1) {
        if (len < 38) return -1;
        is_ipv6 = 1;
    } else {
        return -1;
    }

    size_t offset = 0;

    for (int i = 0; i < 5; i++) {
        buf[offset++] = (contact->id.w[i] >> 24) & 0xFF;
        buf[offset++] = (contact->id.w[i] >> 16) & 0xFF;
        buf[offset++] = (contact->id.w[i] >> 8) & 0xFF;
        buf[offset++] = contact->id.w[i] & 0xFF;
    }

    if (is_ipv6) {
        memcpy(buf + offset, &ipv6, 16);
        offset += 16;
    } else {
        memcpy(buf + offset, &ipv4, 4);
        offset += 4;
    }

    uint16_t port_net = htons(contact->port);
    memcpy(buf + offset, &port_net, 2);
    offset += 2;

    return offset;
}

int kad_contact_from_compact(kad_contact_t *contact, const uint8_t *buf, size_t len) {
    if (!contact || !buf || len < 20) return -1;

    size_t offset = 0;

    for (int i = 0; i < 5; i++) {
        contact->id.w[i] = (uint32_t)buf[offset++] << 24;
        contact->id.w[i] |= (uint32_t)buf[offset++] << 16;
        contact->id.w[i] |= (uint32_t)buf[offset++] << 8;
        contact->id.w[i] |= (uint32_t)buf[offset++];
    }

    // determine addr family based on remaining length
    size_t remaining = len - offset;
    if (remaining == 6) {
        // ipv4: ip (4) + port (2)
        struct in_addr ipv4;
        memcpy(&ipv4, buf + offset, 4);
        offset += 4;

        if (inet_ntop(AF_INET, &ipv4, contact->host, INET6_ADDRSTRLEN) == NULL) {
            return -1;
        }
    } else if (remaining == 18) {
        // ipv6: ip (16) + port (2)
        struct in6_addr ipv6;
        memcpy(&ipv6, buf + offset, 16);
        offset += 16;

        if (inet_ntop(AF_INET6, &ipv6, contact->host, INET6_ADDRSTRLEN) == NULL) {
            return -1;
        }
    } else {
        return -1;
    }

    uint16_t port_net;
    memcpy(&port_net, buf + offset, 2);
    contact->port = ntohs(port_net);

    return 0;
}

int kad_contact_compact_size(const kad_contact_t *contact) {
    if (!contact) return -1;

    struct in_addr ipv4;
    struct in6_addr ipv6;

    if (inet_pton(AF_INET, contact->host, &ipv4) == 1) {
        return 26;
    } else if (inet_pton(AF_INET6, contact->host, &ipv6) == 1) {
        return 38;
    }

    return -1;
}

int kad_contacts_to_compact(const kad_contact_t *contacts, size_t count, uint8_t *buf, size_t len) {
    if (!contacts || !buf || count == 0) return -1;

    size_t offset = 0;

    for (size_t i = 0; i < count; i++) {
        int size = kad_contact_to_compact(&contacts[i], buf + offset, len - offset);
        if (size < 0) {
            return -1;
        }
        offset += size;
    }

    return offset;
}

int kad_contacts_from_compact(
    kad_contact_t *contacts, size_t max_count, const uint8_t *buf, size_t len) {
    if (!contacts || !buf || max_count == 0) return -1;

    size_t offset = 0;
    size_t count = 0;

    // as per mainline dht protocol, all contacts must be the same size
    // (all ipv4 or all ipv6) in batch mode (i.e. no mixing in compact lists)

    if (len % 26 == 0) {
        size_t item_count = len / 26;

        if (item_count > max_count) {
            item_count = max_count;
        }

        for (size_t i = 0; i < item_count; i++) {
            if (kad_contact_from_compact(&contacts[i], buf + offset, 26) < 0) {
                return -1;
            }

            offset += 26;
            count++;
        }
    } else if (len % 38 == 0) {
        size_t item_count = len / 38;

        if (item_count > max_count) {
            item_count = max_count;
        }

        for (size_t i = 0; i < item_count; i++) {
            if (kad_contact_from_compact(&contacts[i], buf + offset, 38) < 0) {
                return -1;
            }

            offset += 38;
            count++;
        }
    } else {
        return -1; // invalid buffer size
    }

    return count;
}

int kad_contact_bencode(const kad_contact_t *contact, uint8_t *buf, size_t len) {
    if (!contact || !buf || len == 0) return -1;

    size_t offset = 0;
    int written;

    if (offset >= len) return -1;

    buf[offset++] = 'd'; // start dictionary

    // notably keys need to be lexicographically ordered, i.e. host > id > port

    size_t host_len = strlen(contact->host);
    written = snprintf((char *)buf + offset, len - offset, "4:host%zu:%s", host_len, contact->host);
    if (written < 0 || offset + written >= len) return -1;
    offset += written;

    written = snprintf((char *)buf + offset, len - offset, "2:id20:");
    if (written < 0 || offset + written >= len) return -1;
    offset += written;

    if (offset + 20 > len) return -1;
    memcpy(buf + offset, contact->id.w, 20);
    offset += 20;

    written = snprintf((char *)buf + offset, len - offset, "4:porti%de", contact->port);
    if (written < 0 || offset + written >= len) return -1;
    offset += written;

    if (offset >= len) return -1;
    buf[offset++] = 'e';

    return offset;
}

static int bdecode_int(const uint8_t *data, size_t len, int64_t *out, size_t *consumed) {
    if (len < 3 || data[0] != 'i') return -1;

    size_t pos = 1;
    int neg = 0;

    if (data[pos] == '-') {
        neg = 1;
        pos++;
    }

    int64_t value = 0;
    int digits = 0;

    while (pos < len && data[pos] != 'e') {
        if (!isdigit(data[pos])) return -1;

        if (digits == 0 && data[pos] == '0' && pos + 1 < len && data[pos + 1] != 'e') {
            return -1; // leading zero
        }

        value = value * 10 + (data[pos] - '0');
        pos++;
        digits++;
    }

    if (pos >= len || data[pos] != 'e' || digits == 0) return -1;

    *out = neg ? -value : value;
    *consumed = pos + 1;

    return 0;
}

static int bdecode_string(
    const uint8_t *data, size_t len, uint8_t **out, size_t *out_len, size_t *consumed) {
    if (len == 0 || !isdigit(data[0])) return -1;

    size_t pos = 0;
    size_t str_len = 0;

    while (pos < len && isdigit(data[pos])) {
        str_len = str_len * 10 + (data[pos] - '0');
        pos++;
    }

    if (pos >= len || data[pos] != ':') return -1;
    pos++;

    if (pos + str_len > len) return -1;

    *out = (uint8_t *)malloc(str_len + 1);
    if (!*out && str_len > 0) return -1;

    if (str_len > 0) {
        memcpy(*out, data + pos, str_len);
    }
    (*out)[str_len] = '\0';

    *out_len = str_len;
    *consumed = pos + str_len;

    return 0;
}

int kad_contact_bdecode(kad_contact_t *contact, const uint8_t *buf, size_t len, size_t *consumed) {
    if (!contact || !buf || len < 10 || buf[0] != 'd') return -1;

    size_t pos = 1;
    int found_id = 0, found_host = 0, found_port = 0;

    while (pos < len && buf[pos] != 'e') {
        uint8_t *key;
        size_t key_len, key_consumed;

        if (bdecode_string(buf + pos, len - pos, &key, &key_len, &key_consumed) < 0) {
            return -1;
        }
        pos += key_consumed;

        if (key_len == 2 && memcmp(key, "id", 2) == 0) {
            uint8_t *id_data;
            size_t id_len, id_consumed;

            if (bdecode_string(buf + pos, len - pos, &id_data, &id_len, &id_consumed) < 0) {
                free(key);
                return -1;
            }

            if (id_len != 20) {
                free(key);
                free(id_data);
                return -1;
            }

            memcpy(contact->id.w, id_data, 20);
            free(id_data);
            pos += id_consumed;
            found_id = 1;
        } else if (key_len == 4 && memcmp(key, "host", 4) == 0) {
            uint8_t *host_data;
            size_t host_len, host_consumed;

            if (bdecode_string(buf + pos, len - pos, &host_data, &host_len, &host_consumed) < 0) {
                free(key);
                return -1;
            }

            if (host_len >= INET6_ADDRSTRLEN) {
                free(key);
                free(host_data);
                return -1;
            }

            // use host_len instead of hardcoded value to support both v4 and v6 addrs
            memcpy(contact->host, host_data, host_len);
            contact->host[host_len] = '\0';
            free(host_data);
            pos += host_consumed;
            found_host = 1;
        } else if (key_len == 4 && memcmp(key, "port", 4) == 0) {
            int64_t port_val;
            size_t port_consumed;

            if (bdecode_int(buf + pos, len - pos, &port_val, &port_consumed) < 0) {
                free(key);
                return -1;
            }

            contact->port = (int)port_val;
            pos += port_consumed;
            found_port = 1;
        } else {
            // todo: skip unknown keys instead of failing
            free(key);
            return -1;
        }

        free(key);
    }

    if (pos >= len || buf[pos] != 'e') return -1;
    pos++;

    if (!found_id || !found_host || !found_port) return -1;

    if (consumed) {
        *consumed = pos;
    }

    return 0;
}
