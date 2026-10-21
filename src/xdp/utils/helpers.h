#pragma once

#include <common/all.h>

#include <linux/bpf.h>

#include <xdp/xdp_helpers.h>
#include <xdp/prog_dispatcher.h>

#ifdef __LIBXDP_STATIC__
#include <bpf_helpers.h>
#else
#include <bpf/bpf_helpers.h>
#endif

#include <xdp/utils/maps.h>

#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define htons(x) ((__be16)___constant_swab16((x)))
#define ntohs(x) ((__be16)___constant_swab16((x)))
#define htonl(x) ((__be32)___constant_swab32((x)))
#define ntohl(x) ((__be32)___constant_swab32((x)))
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define htons(x) (x)
#define ntohs(x) (x)
#define htonl(x) (x)
#define ntohl(x) (x)
#endif

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

static __always_inline int is_ip_in_range(u32 src_ip, u32 net_ip, u8 cidr);

#ifdef ENABLE_IP_RANGE_DROP
static __always_inline int check_ip_range_drop(u32 ip);
#endif

// The source file is included directly below instead of compiled and linked as an object because when linking, there is no guarantee the compiler will inline the function (which is crucial for performance).
// I'd prefer not to include the function logic inside of the header file.
// More Info: https://stackoverflow.com/questions/24289599/always-inline-does-not-work-when-function-is-implemented-in-different-file
#include "helpers.c"
