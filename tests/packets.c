#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <linux/bpf.h>
#include <bpf_helpers.h>
#include <common/all.h>

static void *lookup(const void *map, const void *key);
static long update(const void *map, const void *key, const void *value, u64 flags);
static u64 mock_now(void) { return NANO_TO_SEC; }
static long loop(u32 count, long (*callback)(u32, void *), void *ctx, u64 flags)
{
    for (u32 i = 0; i < count; i++)
    {
        if (callback(i, ctx))
        {
            break;
        }
    }
    return 0;
}

// Use native-sized packet pointers while executing the unchanged XDP entrypoint
// in userspace. BPF helpers are mocked; no kernel maps or interfaces are touched.
struct test_xdp_md { unsigned long data, data_end; };
#define xdp_md test_xdp_md
#define bpf_map_lookup_elem lookup
#define bpf_map_update_elem update
#define bpf_ktime_get_ns() mock_now()
#define bpf_loop loop
#include <xdp/prog.c>

static filter_t filter;
static stats_t counters;
static int blocked;
static u64 expires;
static u128 blocked_ip6;
static int check_block_key;
static void *lookup(const void *map, const void *key)
{
    if (map == &map_stats) return &counters;
    if (map == &map_filters) return *(const u32 *)key == 0 && filter.set ? &filter : NULL;
    if (map == &map_block6 && check_block_key)
    {
        return memcmp(key, &blocked_ip6, 16) == 0 ? &expires : NULL;
    }
    if (map == &map_block || map == &map_block6) return blocked ? &expires : NULL;
    return NULL;
}
static long update(const void *map, const void *key, const void *value, u64 flags)
{
    return 0;
}

static int run(void *data, size_t len)
{
    struct test_xdp_md ctx = {.data = (unsigned long)data, .data_end = (unsigned long)data + len};
    return xdp_prog_main(&ctx);
}

int main(void)
{
    // Ethernet's 14-byte header needs two bytes of headroom for aligned IP/L4.
    _Alignas(8) unsigned char storage[130] = {0};
    unsigned char *packet = storage + 2;
    const size_t packet_len = sizeof(storage) - 2;
    struct ethhdr *eth = (void *)packet;
    struct ipv6hdr *ip6 = (void *)(eth + 1);
    struct icmp6hdr *icmp6 = (void *)(ip6 + 1);
    eth->h_proto = htons(ETH_P_IPV6);
    ip6->version = 6;
    ip6->nexthdr = IPPROTO_ICMPV6;
    ip6->saddr.s6_addr[15] = 1;
    icmp6->icmp6_type = 128;
    filter.set = 1;
    filter.icmp.enabled = 1;
    filter.icmp.do_type = 1;
    filter.icmp.type = 128;
    assert(run(packet, sizeof(*eth) + sizeof(*ip6) + sizeof(*icmp6)) == XDP_DROP);
    filter.icmp.type = 129;
    assert(run(packet, sizeof(*eth) + sizeof(*ip6) + sizeof(*icmp6)) == XDP_PASS);
    filter.icmp.enabled = 0;
    filter.ip.do_src_ip6 = 1;
    memcpy(filter.ip.src_ip6, &ip6->saddr, 16);
    assert(run(packet, packet_len) == XDP_DROP);
    ip6->saddr.s6_addr[15] = 2;
    assert(run(packet, packet_len) == XDP_PASS);
    // Explicit :: must not become a wildcard.
    memset(filter.ip.src_ip6, 0, 16);
    assert(run(packet, packet_len) == XDP_PASS);
    memset(&ip6->saddr, 0, 16);
    assert(run(packet, packet_len) == XDP_DROP);
    assert(run(packet, sizeof(*eth) + sizeof(*ip6)) == XDP_DROP);
    filter.set = 0;
    blocked = 1;
    ip6->nexthdr = IPPROTO_GRE;
    assert(run(packet, packet_len) == XDP_DROP);
    blocked = 0;
    assert(run(packet, packet_len) == XDP_PASS);
    ip6->saddr.s6_addr[15] = 1;
    memcpy(&blocked_ip6, &ip6->saddr, sizeof(blocked_ip6));
    check_block_key = 1;
    assert(run(packet, packet_len) == XDP_DROP);
    ip6->saddr.s6_addr[15] = 2;
    assert(run(packet, packet_len) == XDP_PASS);
    check_block_key = 0;

    memset(packet, 0, packet_len);
    eth->h_proto = htons(ETH_P_IP);
    struct iphdr *ip = (void *)(eth + 1);
    ip->version = 4;
    ip->ihl = 4;
    ip->protocol = IPPROTO_UDP;
    assert(run(packet, packet_len) == XDP_DROP);
    ip->ihl = 5;
    assert(run(packet, packet_len) == XDP_PASS);
    filter = (filter_t){.set = 1};
    filter.ip.do_src_ip = 1;
    filter.ip.src_cidr = 32;
    ip->saddr = htonl(1);
    assert(run(packet, packet_len) == XDP_PASS);
    ip->saddr = 0;
    assert(run(packet, packet_len) == XDP_DROP);
    filter.ip.src_cidr = 0;
    ip->saddr = htonl(0xc0000201);
    assert(run(packet, packet_len) == XDP_DROP);
    assert(is_ip_in_range(0, 0, 0));
    assert(!is_ip_in_range(0, 0, 33));
    puts("Packet regression tests passed.");
    return 0;
}
