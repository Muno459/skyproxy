/*
 ============================================================================
 Name        : hev-ip-pool.c
 Description : IPv6/IPv4 IP pool rotation
 ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "hev-logger.h"
#include "hev-config.h"

#include "hev-ip-pool.h"

static struct in6_addr prefix_addr;
static int prefix_len;
static int initialized;

static uint64_t
fnv1a (const char *data, unsigned int len, uint64_t seed)
{
    uint64_t hash = seed;
    unsigned int i;

    for (i = 0; i < len; i++) {
        hash ^= (uint8_t)data[i];
        hash *= 0x100000001b3ULL;
    }
    return hash;
}

static void
fill_host_bits (struct in6_addr *addr, uint64_t h1, uint64_t h2)
{
    int byte_start = prefix_len / 8;
    int bit_offset = prefix_len % 8;
    unsigned char host_bytes[16];
    int i;

    /* Pack h1 and h2 into 16 bytes of host material */
    for (i = 0; i < 8; i++) {
        host_bytes[i] = (h1 >> (56 - i * 8)) & 0xFF;
        host_bytes[i + 8] = (h2 >> (56 - i * 8)) & 0xFF;
    }

    /* Copy prefix */
    memcpy (addr, &prefix_addr, sizeof (struct in6_addr));

    /* Merge host bits starting at prefix boundary */
    if (bit_offset != 0) {
        unsigned char mask = (0xFF >> bit_offset);
        addr->s6_addr[byte_start] =
            (addr->s6_addr[byte_start] & ~mask) |
            (host_bytes[0] & mask);
        byte_start++;
    }

    for (i = byte_start; i < 16; i++) {
        int hi = i - byte_start + (bit_offset ? 1 : 0);
        if (hi < 16)
            addr->s6_addr[i] = host_bytes[hi];
        else
            addr->s6_addr[i] = 0;
    }
}

int
hev_ip_pool_init (void)
{
    const char *pfx;
    int plen;

    pfx = hev_config_get_ip_pool_ipv6_prefix ();
    if (!pfx)
        return 0;

    plen = hev_config_get_ip_pool_ipv6_prefix_len ();
    if (plen < 1 || plen > 120) {
        LOG_E ("ip-pool: invalid prefix-len %d", plen);
        return -1;
    }

    if (inet_pton (AF_INET6, pfx, &prefix_addr) != 1) {
        LOG_E ("ip-pool: invalid ipv6-prefix '%s'", pfx);
        return -1;
    }

    prefix_len = plen;
    initialized = 1;

    srand (time (NULL) ^ getpid ());

    LOG_I ("ip-pool: initialized %s/%d", pfx, plen);
    return 0;
}

int
hev_ip_pool_get_ipv6 (int mode, const char *key, unsigned int key_len,
                       int ttl, struct sockaddr_in6 *addr)
{
    uint64_t h1, h2;

    if (!initialized)
        return -1;

    memset (addr, 0, sizeof (struct sockaddr_in6));
    addr->sin6_family = AF_INET6;

    switch (mode) {
    case HEV_IP_POOL_MODE_ROTATE:
        h1 = ((uint64_t)rand () << 32) | (uint64_t)rand ();
        h2 = ((uint64_t)rand () << 32) | (uint64_t)rand ();
        break;
    case HEV_IP_POOL_MODE_STICKY:
        if (!key || key_len == 0) {
            h1 = ((uint64_t)rand () << 32) | (uint64_t)rand ();
            h2 = ((uint64_t)rand () << 32) | (uint64_t)rand ();
        } else {
            h1 = fnv1a (key, key_len, 0xcbf29ce484222325ULL);
            h2 = fnv1a (key, key_len, 0x6c62272e07bb0142ULL);
        }
        break;
    case HEV_IP_POOL_MODE_STICKY_TTL:
        if (!key || key_len == 0 || ttl <= 0) {
            h1 = ((uint64_t)rand () << 32) | (uint64_t)rand ();
            h2 = ((uint64_t)rand () << 32) | (uint64_t)rand ();
        } else {
            time_t bucket = time (NULL) / ttl;
            char combined[512];
            unsigned int clen;

            if (key_len > sizeof (combined) - 32)
                key_len = sizeof (combined) - 32;
            memcpy (combined, key, key_len);
            clen = key_len;
            clen += snprintf (combined + key_len,
                              sizeof (combined) - key_len,
                              ":%ld", (long)bucket);

            h1 = fnv1a (combined, clen, 0xcbf29ce484222325ULL);
            h2 = fnv1a (combined, clen, 0x6c62272e07bb0142ULL);
        }
        break;
    default:
        return -1;
    }

    fill_host_bits (&addr->sin6_addr, h1, h2);

    LOG_D ("ip-pool: mode=%d generated address", mode);
    return 0;
}

void
hev_ip_pool_fini (void)
{
    initialized = 0;
}
