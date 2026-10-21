#pragma once

#include <common/int_types.h>

struct filter_ip
{
    unsigned int do_src_ip : 1;
    unsigned int do_dst_ip : 1;
    u32 src_ip;
    u8 src_cidr;

    u32 dst_ip;
    u8 dst_cidr;

#ifdef ENABLE_IPV6
    unsigned int do_src_ip6 : 1;
    unsigned int do_dst_ip6 : 1;
    u32 src_ip6[4];
    u32 dst_ip6[4];
#endif

    unsigned int do_min_ttl : 1;
    u8 min_ttl;

    unsigned int do_max_ttl : 1;
    u8 max_ttl;

    unsigned int do_min_len : 1;
    u16 min_len;

    unsigned int do_max_len : 1;
    u16 max_len;

    unsigned int do_tos : 1;
    u8 tos;
} typedef filter_ip_t;

struct filter_tcp
{
    unsigned int enabled : 1;

    unsigned int do_sport_min : 1;
    u16 sport_min;

    unsigned int do_sport_max : 1;
    u16 sport_max;

    unsigned int do_dport_min : 1;
    u16 dport_min;

    unsigned int do_dport_max : 1;
    u16 dport_max;

    // TCP flags.
    unsigned int do_urg : 1;
    unsigned int urg : 1;

    unsigned int do_ack : 1;
    unsigned int ack : 1;

    unsigned int do_rst : 1;
    unsigned int rst : 1;

    unsigned int do_psh : 1;
    unsigned int psh : 1;

    unsigned int do_syn : 1;
    unsigned int syn : 1;

    unsigned int do_fin : 1;
    unsigned int fin : 1;

    unsigned int do_ece : 1;
    unsigned int ece : 1;

    unsigned int do_cwr : 1;
    unsigned int cwr : 1;
} typedef filter_tcp_t;

struct filter_udp
{
    unsigned int enabled : 1;

    unsigned int do_sport_min : 1;
    u16 sport_min;

    unsigned int do_sport_max : 1;
    u16 sport_max;

    unsigned int do_dport_min : 1;
    u16 dport_min;

    unsigned int do_dport_max : 1;
    u16 dport_max;
} typedef filter_udp_t;

struct filter_icmp
{
    unsigned int enabled : 1;

    unsigned int do_code : 1;
    u8 code;

    unsigned int do_type : 1;
    u8 type;
} typedef filter_icmp_t;

struct filter
{
    unsigned int set : 1;
    unsigned int log : 1;
    unsigned int enabled : 1;

    u8 action;
    u16 block_time;

#ifdef ENABLE_RL_IP
    unsigned int do_ip_pps : 1;
    u64 ip_pps;

    unsigned int do_ip_bps : 1;
    u64 ip_bps;
#endif

#ifdef ENABLE_RL_FLOW
    unsigned int do_flow_pps : 1;
    u64 flow_pps;

    unsigned int do_flow_bps : 1;
    u64 flow_bps;
#endif
    
    filter_ip_t ip;

    filter_tcp_t tcp;
    filter_udp_t udp;
    filter_icmp_t icmp;
} __attribute__((__aligned__(8))) typedef filter_t;

struct stats
{
    u64 allowed;
    u64 dropped;
    u64 passed;
} typedef stats_t;

struct cl_stats
{
    u64 pps;
    u64 bps;
    u64 next_update;
} typedef cl_stats_t;

struct flow
{
    u32 ip;
    u16 port;
    u8 protocol;
} typedef flow_t;

struct flow6
{
    u128 ip;
    u16 port;
    u8 protocol;
} typedef flow6_t;

struct filter_log_event
{
    u64 ts;
    int filter_id;

    int length;

    u32 src_ip;
    u32 src_ip6[4];

    u16 src_port;

    u32 dst_ip;
    u32 dst_ip6[4];

    u16 dst_port;

    u8 protocol;

    u64 ip_pps;
    u64 ip_bps;

    u64 flow_pps;
    u64 flow_bps;
} typedef filter_log_event_t;

struct lpm_trie_key
{
    u32 prefix_len;
    u32 data;
} typedef lpm_trie_key_t;
