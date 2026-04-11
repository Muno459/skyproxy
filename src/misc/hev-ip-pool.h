/*
 ============================================================================
 Name        : hev-ip-pool.h
 Description : IPv6/IPv4 IP pool rotation
 ============================================================================
 */

#ifndef __HEV_IP_POOL_H__
#define __HEV_IP_POOL_H__

#include <netinet/in.h>

#ifdef __cplusplus
extern "C" {
#endif

#define HEV_IP_POOL_MODE_ROTATE 0
#define HEV_IP_POOL_MODE_STICKY 1
#define HEV_IP_POOL_MODE_STICKY_TTL 2

int hev_ip_pool_init (void);

int hev_ip_pool_get_ipv6 (int mode, const char *key, unsigned int key_len,
                           int ttl, struct sockaddr_in6 *addr);

void hev_ip_pool_fini (void);

#ifdef __cplusplus
}
#endif

#endif /* __HEV_IP_POOL_H__ */
