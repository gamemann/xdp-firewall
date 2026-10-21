#include <xdp/utils/helpers.h>

/**
 * Checks if an IP is within a specific CIDR range.
 * 
 * @param src_ip The source/main IP to check against.
 * @param net_ip The network IP.
 * @param cidr The CIDR range.
 * 
 * @return 1 on yes, 0 on no.
 */
static __always_inline int is_ip_in_range(u32 src_ip, u32 net_ip, u8 cidr)
{
    if (cidr == 0)
    {
        return 1;
    }
    if (cidr > 32)
    {
        return 0;
    }
    return !((src_ip ^ net_ip) & htonl(0xFFFFFFFFu << (32 - cidr)));
}

#ifdef ENABLE_IP_RANGE_DROP
/**
 * Checks if the IP is in the IP range drop map.
 * 
 * @param ip The IP address.
 * 
 * @return 1 on yes or 0 on no.
 */
static __always_inline int check_ip_range_drop(u32 ip)
{
    lpm_trie_key_t key = {0};
    key.prefix_len = 32;
    key.data = ip;

    u64 *lookup = bpf_map_lookup_elem(&map_range_drop, &key);

    if (lookup)
    {
        u32 bit_mask = *lookup >> 32;
        u32 prefix = *lookup & 0xFFFFFFFF;

        // Check if matched.
        if ((ip & bit_mask) == prefix)
        {
            return 1;
        }
    }

    return 0;
}
#endif
