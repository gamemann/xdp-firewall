#include <loader/utils/xdp.h>

/**
 * Finds a BPF map's FD.
 * 
 * @param prog A pointer to the XDP program structure.
 * @param mapname The name of the map to retrieve.
 * 
 * @return The map's FD.
 */
int get_map_fd(struct xdp_program *prog, const char *map_name)
{
    int fd = -1;

    struct bpf_object *obj = xdp_program__bpf_obj(prog);

    if (obj == NULL)
    {
        fprintf(stderr, "Error finding BPF object from XDP program.\n");

        goto out;
    }

    struct bpf_map *map = bpf_object__find_map_by_name(obj, map_name);

    if (!map) 
    {
        fprintf(stderr, "Error finding eBPF map: %s\n", map_name);

        goto out;
    }

    fd = bpf_map__fd(map);

    out:
        return fd;
}

/**
 * Custom print function for LibBPF that doesn't print anything (silent mode).
 * 
 * @param level The current LibBPF log level.
 * @param format The message format.
 * @param args Format arguments for the message.
 * 
 * @return void
 */
static int libbpf_silent(enum libbpf_print_level level, const char *format, va_list args)
{
    return 0;
}

/**
 * Sets custom LibBPF log mode.
 * 
 * @param silent If 1, disables LibBPF logging entirely.
 * 
 * @return void
 */
void set_libbpf_log_mode(int silent)
{
    if (silent)
    {
        libbpf_set_print(libbpf_silent);
    }
}

/**
 * Loads a BPF object file.
 * 
 * @param file_name The path to the BPF object file.
 * 
 * @return XDP program structure (pointer) or NULL.
 */
struct xdp_program *load_bpf_obj(const char *file_name)
{
    struct xdp_program *prog = xdp_program__open_file(file_name, "xdp_prog", NULL);

    if (prog == NULL)
    {
        // The main function handles this error.
        return NULL;
    }

    return prog;
}

/**
 * Retrieves BPF object from XDP program.
 * 
 * @param prog A pointer to the XDP program.
 * 
 * @return The BPF object.
 */
struct bpf_object* get_bpf_obj(struct xdp_program* prog)
{
    return xdp_program__bpf_obj(prog);
}

/**
 * Attempts to attach or detach (progfd = -1) a BPF/XDP program to an interface.
 * 
 * @param prog A pointer to the XDP program structure.
 * @param mode_used The mode being used.
 * @param ifidx The index to the interface to attach to.
 * @param detach If above 0, attempts to detach XDP program.
 * @param force_skb If set, forces the XDP program to run in SKB mode.
 * @param force_offload If set, forces the XDP program to run in offload mode.
 * 
 * @return 0 on success and 1 on error.
 */
int attach_xdp(struct xdp_program *prog, char** mode, int ifidx, int detach, int force_skb, int force_offload)
{
    // Before attaching, set chaining options.
    xdp_program__set_run_prio(prog, XDP_MULTIPROG_PRIORITY);
    xdp_program__set_chain_call_enabled(prog, XDP_MULTIPROG_ACTION, XDP_MULTIPROG_ENABLED);

    u32 attach_mode = XDP_MODE_NATIVE;

    *mode = "DRV/native";

    if (force_offload)
    {
        *mode = "HW/offload";

        attach_mode = XDP_MODE_HW;
    }
    else if (force_skb)
    {
        *mode = "SKB/generic";
        
        attach_mode = XDP_MODE_SKB;
    }

    int exit = 0;

    while (!exit)
    {
        // Try loading program with current mode.
        int err;

        if (detach)
        {
            err = xdp_program__detach(prog, ifidx, attach_mode, 0);
        }
        else
        {
            err = xdp_program__attach(prog, ifidx, attach_mode, 0);
        }

        if (err)
        {
            // Decrease mode.
            switch (attach_mode)
            {
                case XDP_MODE_HW:
                    attach_mode = XDP_MODE_NATIVE;
                    *mode = "DRV/native";

                    break;

                case XDP_MODE_NATIVE:
                    attach_mode = XDP_MODE_SKB;
                    *mode = "SKB/generic";

                    break;

                case XDP_MODE_SKB:
                    // Exit loop.
                    exit = 1;

                    *mode = NULL;
                    
                    break;
            }

            // Retry.
            continue;
        }
        
        // Success, so break current loop.
        break;
    }

    // If exit is set to 1 or smode is NULL, it indicates full failure.
    if (exit || *mode == NULL)
    {
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

/**
 * Deletes a filter.
 * 
 * @param map_filters The filters BPF map FD.
 * @param idx The filter index to delete.
 * 
 * @return 0 on success or the error value of bpf_map_delete_elem().
 */
int delete_filter(int map_filters, u32 idx)
{
    int cpus = libbpf_num_possible_cpus();
    if (cpus < 1)
    {
        return -1;
    }
    filter_t *empty = calloc(cpus, sizeof(*empty));
    if (!empty)
    {
        return -1;
    }
    // Array maps cannot delete elements; an unset value terminates matching.
    int ret = bpf_map_update_elem(map_filters, &idx, empty, BPF_ANY);
    free(empty);
    return ret;
}

/**
 * Deletes all filters.
 * 
 * @param map_filters The filters BPF map FD.
 * 
 * @return void
 */
void delete_filters(int map_filters)
{
    for (int i = 0; i < MAX_FILTERS; i++)
    {
        delete_filter(map_filters, i);
    }
}

/**
 * Updates a filter rule.
 * 
 * @param map_filters The filters BPF map FD.
 * @param filter_cfg A pointer to the filter config rule.
 * @param idx The filter index to insert or update.
 * 
 * @return 0 on success or error value of bpf_map_update_elem().
 */
static int update_filter_cpus(int map_filters, filter_rule_cfg_t* filter_cfg, int idx, filter_t *filter_cpus, int cpus)
{
    if (validate_filter(filter_cfg) != 0)
    {
        return -1;
    }
    filter_t filter = {0};
    filter.action = 1;
    filter.block_time = 1;

    filter.set = filter_cfg->set;

    if (!filter_cfg->enabled)
    {
        return 0;
    }
    
    if (filter_cfg->enabled > -1)
    {
        filter.enabled = filter_cfg->enabled;
    }

    if (filter_cfg->log > -1)
    {
        filter.log = filter_cfg->log;
    }

    if (filter_cfg->action > -1)
    {
        filter.action = filter_cfg->action;
    }

    if (filter_cfg->block_time > -1)
    {
        filter.block_time = filter_cfg->block_time;
    }

#ifdef ENABLE_RL_IP
    if (filter_cfg->ip_pps > -1)
    {
        filter.do_ip_pps = 1;

        filter.ip_pps = (u64) filter_cfg->ip_pps;
    }

    if (filter_cfg->ip_bps > -1)
    {
        filter.do_ip_bps = 1;

        filter.ip_bps = (u64) filter_cfg->ip_bps;
    }
#endif

#ifdef ENABLE_RL_FLOW
    if (filter_cfg->flow_pps > -1)
    {
        filter.do_flow_pps = 1;

        filter.flow_pps = (u64) filter_cfg->flow_pps;
    }

    if (filter_cfg->flow_bps > -1)
    {
        filter.do_flow_bps = 1;

        filter.flow_bps = (u64) filter_cfg->flow_bps;
    }
#endif

    if (filter_cfg->ip.src_ip)
    {
        ip_range_t ip_range = parse_ip_range(filter_cfg->ip.src_ip);
        if (!ip_range.success)
        {
            return -1;
        }

        filter.ip.do_src_ip = 1;
        filter.ip.src_ip = ip_range.ip;
        filter.ip.src_cidr = ip_range.cidr;
    }

    if (filter_cfg->ip.dst_ip)
    {
        ip_range_t ip_range = parse_ip_range(filter_cfg->ip.dst_ip);
        if (!ip_range.success)
        {
            return -1;
        }

        filter.ip.do_dst_ip = 1;
        filter.ip.dst_ip = ip_range.ip;
        filter.ip.dst_cidr = ip_range.cidr;
    }

#ifdef ENABLE_IPV6
    if (filter_cfg->ip.src_ip6)
    {
        struct in6_addr in;

        if (inet_pton(AF_INET6, filter_cfg->ip.src_ip6, &in) != 1)
        {
            return -1;
        }
        filter.ip.do_src_ip6 = 1;
        memcpy(filter.ip.src_ip6, &in, sizeof(filter.ip.src_ip6));
    }

    if (filter_cfg->ip.dst_ip6)
    {
        struct in6_addr in;

        if (inet_pton(AF_INET6, filter_cfg->ip.dst_ip6, &in) != 1)
        {
            return -1;
        }
        filter.ip.do_dst_ip6 = 1;
        memcpy(filter.ip.dst_ip6, &in, sizeof(filter.ip.dst_ip6));
    }
#endif

    if (filter_cfg->ip.min_ttl > -1)
    {
        filter.ip.do_min_ttl = 1;

        filter.ip.min_ttl = filter_cfg->ip.min_ttl;
    }

    if (filter_cfg->ip.max_ttl > -1)
    {
        filter.ip.do_max_ttl = 1;

        filter.ip.max_ttl = filter_cfg->ip.max_ttl;
    }

    if (filter_cfg->ip.min_len > -1)
    {
        filter.ip.do_min_len = 1;

        filter.ip.min_len = filter_cfg->ip.min_len;
    }

    if (filter_cfg->ip.max_len > -1)
    {
        filter.ip.do_max_len = 1;

        filter.ip.max_len = filter_cfg->ip.max_len;
    }

    if (filter_cfg->ip.tos > -1)
    {
        filter.ip.do_tos = 1;

        filter.ip.tos = filter_cfg->ip.tos;
    }

    if (filter_cfg->tcp.enabled > -1)
    {
        filter.tcp.enabled = filter_cfg->tcp.enabled;
    }

    port_range_t tcp_src_port_range = parse_port_range(filter_cfg->tcp.sport);
    if (filter_cfg->tcp.sport && !tcp_src_port_range.success)
    {
        return -1;
    }

    if (tcp_src_port_range.success)
    {
        filter.tcp.do_sport_min = 1;
        filter.tcp.do_sport_max = 1;

        filter.tcp.sport_min = tcp_src_port_range.min;
        filter.tcp.sport_max = tcp_src_port_range.max;
    }

    port_range_t tcp_dst_port_range = parse_port_range(filter_cfg->tcp.dport);
    if (filter_cfg->tcp.dport && !tcp_dst_port_range.success)
    {
        return -1;
    }

    if (tcp_dst_port_range.success)
    {
        filter.tcp.do_dport_min = 1;
        filter.tcp.do_dport_max = 1;

        filter.tcp.dport_min = tcp_dst_port_range.min;
        filter.tcp.dport_max = tcp_dst_port_range.max;
    }

    if (filter_cfg->tcp.urg > -1)
    {
        filter.tcp.do_urg = 1;

        filter.tcp.urg = filter_cfg->tcp.urg;
    }

    if (filter_cfg->tcp.ack > -1)
    {
        filter.tcp.do_ack = 1;

        filter.tcp.ack = filter_cfg->tcp.ack;
    }

    if (filter_cfg->tcp.rst > -1)
    {
        filter.tcp.do_rst = 1;

        filter.tcp.rst = filter_cfg->tcp.rst;
    }

    if (filter_cfg->tcp.psh > -1)
    {
        filter.tcp.do_psh = 1;

        filter.tcp.psh = filter_cfg->tcp.psh;
    }

    if (filter_cfg->tcp.syn > -1)
    {
        filter.tcp.do_syn = 1;

        filter.tcp.syn = filter_cfg->tcp.syn;
    }

    if (filter_cfg->tcp.fin > -1)
    {
        filter.tcp.do_fin = 1;

        filter.tcp.fin = filter_cfg->tcp.fin;
    }

    if (filter_cfg->tcp.ece > -1)
    {
        filter.tcp.do_ece = 1;

        filter.tcp.ece = filter_cfg->tcp.ece;
    }

    if (filter_cfg->tcp.cwr > -1)
    {
        filter.tcp.do_cwr = 1;

        filter.tcp.cwr = filter_cfg->tcp.cwr;
    }

    if (filter_cfg->udp.enabled > -1)
    {
        filter.udp.enabled = filter_cfg->udp.enabled;
    }

    port_range_t udp_src_port_range = parse_port_range(filter_cfg->udp.sport);
    if (filter_cfg->udp.sport && !udp_src_port_range.success)
    {
        return -1;
    }

    if (udp_src_port_range.success)
    {
        filter.udp.do_sport_min = 1;
        filter.udp.do_sport_max = 1;

        filter.udp.sport_min = udp_src_port_range.min;
        filter.udp.sport_max = udp_src_port_range.max;
    }

    port_range_t udp_dst_port_range = parse_port_range(filter_cfg->udp.dport);
    if (filter_cfg->udp.dport && !udp_dst_port_range.success)
    {
        return -1;
    }

    if (udp_dst_port_range.success)
    {
        filter.udp.do_dport_min = 1;
        filter.udp.do_dport_max = 1;

        filter.udp.dport_min = udp_dst_port_range.min;
        filter.udp.dport_max = udp_dst_port_range.max;
    }

    if (filter_cfg->icmp.enabled > -1)
    {
        filter.icmp.enabled = filter_cfg->icmp.enabled;
    }

    if (filter_cfg->icmp.code > -1)
    {
        filter.icmp.do_code = 1;

        filter.icmp.code = filter_cfg->icmp.code;
    }

    if (filter_cfg->icmp.type > -1)
    {
        filter.icmp.do_type = 1;

        filter.icmp.type = filter_cfg->icmp.type;
    }

    for (int j = 0; j < cpus; j++)
    {
        filter_cpus[j] = filter;
    }

    return bpf_map_update_elem(map_filters, &idx, filter_cpus, BPF_ANY);
}

int update_filter(int map_filters, filter_rule_cfg_t* filter_cfg, int idx)
{
    int cpus = libbpf_num_possible_cpus();
    if (cpus < 1 || idx < 0 || idx >= MAX_FILTERS)
    {
        return -1;
    }
    if (!filter_cfg->set || !filter_cfg->enabled)
    {
        return delete_filter(map_filters, idx);
    }
    filter_t *values = calloc(cpus, sizeof(*values));
    if (!values)
    {
        return -1;
    }
    int ret = update_filter_cpus(map_filters, filter_cfg, idx, values, cpus);
    free(values);
    return ret;
}

/**
 * Updates the filter's BPF map with current config settings.
 * 
 * @param map_filters The filter's BPF map FD.
 * @param cfg A pointer to the config structure.
 * 
 * @return 0 on success or -1 on failure.
 */
int update_filters(int map_filters, config__t *cfg)
{
    int ret = 0;
    int cur_idx = 0;
    int cpus = libbpf_num_possible_cpus();
    if (cpus < 1)
    {
        return -1;
    }
    filter_t *values = calloc(cpus, sizeof(*values));
    if (!values)
    {
        return -1;
    }

    // Add a filter to the filter maps.
    for (int i = 0; i < MAX_FILTERS; i++)
    {
        filter_rule_cfg_t* filter = &cfg->filters[i];

        // Only insert set and enabled filters.
        if (!filter->set || !filter->enabled)
        {
            continue;
        }

        // Attempt to update filter.
        if ((ret = update_filter_cpus(map_filters, filter, cur_idx, values, cpus)) != 0)
        {
            fprintf(stderr, "[WARNING] Failed to update filter #%d due to BPF update error (%d)...\n", cur_idx, ret);

            break;
        }

        cur_idx++;
    }
    if (ret != 0)
    {
        free(values);
        return ret;
    }
    // Invalidate the old tail after shrinking or disabling rules. The kernel
    // stops at this sentinel, so clearing every remaining slot is unnecessary.
    if (cur_idx < MAX_FILTERS)
    {
        memset(values, 0, cpus * sizeof(*values));
        if (bpf_map_update_elem(map_filters, &cur_idx, values, BPF_ANY) != 0)
        {
            ret = -1;
        }
    }
    free(values);
    return ret;
}

/**
 * Pins a BPF map to the file system.
 * 
 * @param obj A pointer to the BPF object.
 * @param pin_dir The pin directory.
 * @param map_name The map name.
 * 
 * @return 0 on success or value of bpf_map__pin() on error.
 */
int pin_bpf_map(struct bpf_object* obj, const char* pin_dir, const char* map_name)
{
    struct bpf_map* map = bpf_object__find_map_by_name(obj, map_name);

    if (!map)
    {
        return -1;
    }

    char full_path[255];
    snprintf(full_path, sizeof(full_path), "%s/%s", XDP_MAP_PIN_DIR, map_name);

    return bpf_map__pin(map, full_path);
}

/**
 * Unpins a BPF map from the file system.
 * 
 * @param obj A pointer to the BPF object.
 * @param pin_dir The pin directory.
 * @param map_name The map name.
 * 
 * @return
 */
int unpin_bpf_map(struct bpf_object* obj, const char* pin_dir, const char* map_name)
{
    struct bpf_map* map = bpf_object__find_map_by_name(obj, map_name);

    if (!map)
    {
        return 1;
    }

    char full_path[255];
    snprintf(full_path, sizeof(full_path), "%s/%s", XDP_MAP_PIN_DIR, map_name);

    return bpf_map__unpin(map, full_path);
}

/**
 * Retrieves a map FD on the file system (pinned).
 * 
 * @param pin_dir The pin directory.
 * @param map_name The map name.
 * 
 * @return The map FD or -1 on error.
 */
int get_map_fd_pin(const char* pin_dir, const char* map_name)
{
    char full_path[255];
    snprintf(full_path, sizeof(full_path), "%s/%s", pin_dir, map_name);

    return bpf_obj_get(full_path);
}

/**
 * Deletes IPv4 address from block map.
 * 
 * @param map_block The block map's FD.
 * @param ip The IP address to remove.
 * 
 * @return 0 on success or error value of bpf_map_delete_elem().
 */
int delete_block(int map_block, u32 ip)
{
    return bpf_map_delete_elem(map_block, &ip);
}

/**
 * Adds an IPv4 address to the block map.
 * 
 * @param map_block The block map's FD.
 * @param ip The IP address to add.
 * @param expires When the block expires (nanoseconds since system boot).
 * 
 * @return 0 on success or error value of bpf_map_update_elem().
 */
int add_block(int map_block, u32 ip, u64 expires)
{
    return bpf_map_update_elem(map_block, &ip, &expires, BPF_ANY);
}

/**
 * Deletes IPv6 address from block map.
 * 
 * @param map_block6 The block map's FD.
 * @param ip The IP address to remove.
 * 
 * @return 0 on success or error value of bpf_map_delete_elem().
 */
int delete_block6(int map_block6, u128 ip)
{
    return bpf_map_delete_elem(map_block6, &ip);
}

/**
 * Adds an IPv6 address to the block map.
 * 
 * @param map_block6 The block map's FD.
 * @param ip The IP address to add.
 * @param expires When the block expires (nanoseconds since system boot).
 * 
 * @return 0 on success or error value of bpf_map_update_elem().
 */
int add_block6(int map_block6, u128 ip, u64 expires)
{
    return bpf_map_update_elem(map_block6, &ip, &expires, BPF_ANY);
}

/**
 * Deletes an IPv4 range from the drop map.
 * 
 * @param map_range_drop The IPv4 range drop map's FD.
 * @param net The network IP.
 * @param cidr The network's CIDR.
 * 
 * @return 0 on success or error value of bpf_map_delete_elem(). 
 */
int delete_range_drop(int map_range_drop, u32 net, u8 cidr)
{
    if (cidr > 32)
    {
        return -1;
    }
    u32 bit_mask = cidr ? htonl(0xFFFFFFFFu << (32 - cidr)) : 0;
    u32 start = net & bit_mask;

    lpm_trie_key_t key = {0};
    key.prefix_len = cidr;
    key.data = start;

    return bpf_map_delete_elem(map_range_drop, &key);
}

/**
 * Adds an IPv4 range to the drop map.
 * 
 * @param map_range_drop The IPv4 range drop map's FD.
 * @param net The network IP.
 * @param cidr The network's CIDR.
 * 
 * @return 0 on success or error value of bpf_map_update_elem(). 
 */
int add_range_drop(int map_range_drop, u32 net, u8 cidr)
{
    if (cidr > 32)
    {
        return -1;
    }
    u32 bit_mask = cidr ? htonl(0xFFFFFFFFu << (32 - cidr)) : 0;
    u32 start = net & bit_mask;

    lpm_trie_key_t key = {0};
    key.prefix_len = cidr;
    key.data = start;

    u64 val = ( (u64)bit_mask << 32 ) | start;

    return bpf_map_update_elem(map_range_drop, &key, &val, BPF_ANY);
}

/**
 * Updates IP ranges from config file.
 * 
 * @param map_range_drop The IPv4 range drop map's FD.
 * @param cfg A pointer to the config file
 * 
 * @return void
 */
void update_range_drops(int map_range_drop, config__t* cfg)
{
    for (int i = 0; i < MAX_IP_RANGES; i++)
    {
        const char* range = cfg->drop_ranges[i];

        if (!range)
        {
            continue;
        }

        // Parse IP range string and return network IP and CIDR.
        ip_range_t t = parse_ip_range(range);
        if (!t.success)
        {
            fprintf(stderr, "[WARNING] Invalid IP drop range: %s\n", range);
            continue;
        }

        add_range_drop(map_range_drop, t.ip, t.cidr);
    }
}