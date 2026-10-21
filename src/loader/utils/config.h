#pragma once

#include <common/all.h>

#include <stdio.h>
#include <stdlib.h>
#include <libconfig.h>
#include <string.h>

#include <arpa/inet.h>

#include <loader/utils/helpers.h>

#define CONFIG_DEFAULT_PATH "/etc/xdpfw/xdpfw.conf"

struct filter_rule_ip_opts
{
    char* src_ip;
    char* dst_ip;

    char* src_ip6;
    char* dst_ip6;

    int min_ttl;
    int max_ttl;

    int min_len;
    int max_len;

    int tos;
} typedef filter_rule_ip_opts_t;

struct filter_rule_filter_tcp
{
    int enabled;

    char* sport;
    char* dport;

    int urg;
    int ack;
    int rst;
    int psh;
    int syn;
    int fin;
    int ece;
    int cwr;
} typedef filter_rule_filter_tcp_t;

struct filter_rule_filter_udp
{
    int enabled;

    char* sport;
    char* dport;
} typedef filter_rule_filter_udp_t;

struct filter_rule_filter_icmp
{
    int enabled;

    int code;
    int type;
} typedef filter_rule_filter_icmp_t;

struct filter_rule_cfg
{
    int set;
    int log;
    int enabled;

    int action;
    int block_time;

    s64 ip_pps;
    s64 ip_bps;

    s64 flow_pps;
    s64 flow_bps;

    filter_rule_ip_opts_t ip;
    
    filter_rule_filter_tcp_t tcp;
    filter_rule_filter_udp_t udp;
    filter_rule_filter_icmp_t icmp;
} typedef filter_rule_cfg_t;

struct config
{
    int verbose;
    char *log_file;
    unsigned int pin_maps : 1;
    int update_time;
    unsigned int no_stats : 1;
    unsigned int stats_per_second : 1;
    int stdout_update_time;

    int interfaces_cnt;
    char* interfaces[MAX_INTERFACES];

    int filters_cnt;
    filter_rule_cfg_t filters[MAX_FILTERS];
    
    int drop_ranges_cnt;
    char* drop_ranges[MAX_IP_RANGES];
} typedef config__t; // config_t is taken by libconfig -.-

struct config_overrides
{
    int verbose;
    const char* log_file;
    const char* interface;
    int pin_maps;
    int update_time;
    int no_stats;
    int stats_per_second;
    int stdout_update_time;
} typedef config_overrides_t;

void set_cfg_defaults(config__t *cfg);
void set_filter_defaults(filter_rule_cfg_t* filter);

void print_cfg(config__t* cfg);
void print_filter(filter_rule_cfg_t* filter, int idx);

int load_cfg(config__t *cfg, const char* cfg_file, int load_defaults, config_overrides_t* overrides);
int save_cfg(config__t* cfg, const char* file_path);

int open_cfg(FILE** file, const char *file_name);
int close_cfg(FILE* file);
int read_cfg(FILE* file, char** buffer);
int parse_cfg(config__t *cfg, const char* data, config_overrides_t* overrides);
int validate_filter(const filter_rule_cfg_t *filter);

int get_next_filter_idx(config__t* cfg);
int get_next_ip_drop_range_idx(config__t* cfg);

#include <loader/utils/logging.h>