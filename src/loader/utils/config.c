#include <loader/utils/config.h>

/**
 * Loads the config from the file system.
 * 
 * @param cfg A pointer to the config structure.
 * @param cfg_file The path to the config file.
 * @param load_defaults Whether to load defaults or not.
 * @param overrides Overrides to use instead of config values.
 * 
 * @return 0 on success or 1 on error.
 */
int load_cfg(config__t *cfg, const char* cfg_file, int load_defaults, config_overrides_t* overrides)
{
    int ret;
    config__t replacement = {0};
    config__t *target = load_defaults ? &replacement : cfg;

    if (load_defaults)
    {
        set_cfg_defaults(target);
    }
    
    FILE *file = NULL;
    
    // Open config file.
    if ((ret = open_cfg(&file, cfg_file)) != 0 || file == NULL)
    {
        fprintf(stderr, "Error opening config file.\n");
        free_cfg(&replacement);
        return ret;
    }

    char* buffer = NULL;

    // Read config.
    if ((ret = read_cfg(file, &buffer)) != 0)
    {
        fprintf(stderr, "Error reading config file.\n");

        close_cfg(file);
        free_cfg(&replacement);

        return ret;
    }

    // Parse config.
    if ((ret = parse_cfg(target, buffer, overrides)) != 0)
    {
        fprintf(stderr, "Error parsing config file.\n");

        close_cfg(file);
        free(buffer);
        free_cfg(&replacement);

        return ret;
    }

    free(buffer);

    if ((ret = close_cfg(file)) != 0)
    {
        fprintf(stderr, "Error closing config file.\n");
        free_cfg(&replacement);

        return ret;
    }

    if (load_defaults)
    {
        free_cfg(cfg);
        *cfg = replacement;
    }
    return EXIT_SUCCESS;
}

/**
 * Opens the config file.
 * 
 * @param file_name Path to config file.
 * 
 * @return 0 on success or 1 on error.
 */
int open_cfg(FILE** file, const char *file_name)
{
    // Close any existing files.
    if (*file != NULL)
    {
        fclose(*file);

        *file = NULL;
    }

    *file = fopen(file_name, "r");

    if (*file == NULL)
    {
        return 1;
    }

    return 0;
}

/**
 * Close config file.
 * 
 * @param file A pointer to the file to close.
 * 
 * @param return 0 on success or error value of fclose().
 */
int close_cfg(FILE* file)
{
    return fclose(file);
}

/**
 * Reads contents from the config file.
 * 
 * @param file The file pointer.
 * @param buffer The buffer to store the data in (manually allocated).
 */
int read_cfg(FILE* file, char** buffer)
{
    if (fseek(file, 0, SEEK_END) != 0)
    {
        return 1;
    }
    long file_size = ftell(file);
    rewind(file);

    if (file_size <= 0)
    {
        return 1;
    }

    *buffer = malloc(file_size + 1);

    if (*buffer == NULL)
    {
        return 1;
    }

    size_t read = fread(*buffer, 1, file_size, file);
    if (read != (size_t)file_size || ferror(file))
    {
        free(*buffer);
        *buffer = NULL;
        return 1;
    }
    (*buffer)[read] = '\0';

    return 0;
}

/**
 * Read the config file and stores values in config structure.
 * 
 * @param cfg A pointer to the config structure.
 * @param data The config data.
 * @param overrides Overrides to use instead of config values.
 * 
 * @return 0 on success or 1/-1 on error.
 */
int parse_cfg(config__t *cfg, const char* data, config_overrides_t* overrides)
{
    // Initialize config.
    config_t conf;
    config_setting_t *setting;

    config_init(&conf);

    // Attempt to read the config.
    if (config_read_string(&conf, data) == CONFIG_FALSE)
    {
        fprintf(stderr, "Error from LibConfig when reading file - %s (Line %d)\n", config_error_text(&conf), config_error_line(&conf));

        config_destroy(&conf);

        return EXIT_FAILURE;
    }

    setting = config_lookup(&conf, "filters");
    if (setting && (!config_setting_is_list(setting) || config_setting_length(setting) > MAX_FILTERS))
    {
        fprintf(stderr, "Filters must be a list with at most %d entries.\n", MAX_FILTERS);
        config_destroy(&conf);
        return EXIT_FAILURE;
    }

    int verbose;

    if (config_lookup_int(&conf, "verbose", &verbose) == CONFIG_TRUE || (overrides && overrides->verbose > -1))
    {
        if (overrides && overrides->verbose > -1)
        {
            cfg->verbose = overrides->verbose;
        }
        else
        {
            cfg->verbose = verbose;
        }
    }

    const char* log_file;

    if (config_lookup_string(&conf, "log_file", &log_file) == CONFIG_TRUE || (overrides && overrides->log_file != NULL))
    {
        // We must free previous value to prevent memory leak.
        if (cfg->log_file != NULL)
        {
            free(cfg->log_file);
            cfg->log_file = NULL;
        }

        if (overrides && overrides->log_file != NULL)
        {
            if (strlen(overrides->log_file) > 0)
            {
                cfg->log_file = strdup(overrides->log_file);
                
            }
            else
            {
                cfg->log_file = NULL;
            }
        }
        else
        {
            if (strlen(log_file) > 0)
            {
                cfg->log_file = strdup(log_file);
            }
            else
            {
                cfg->log_file = NULL;
            }
        }
    }

    // Get interface(s).
    config_setting_t* interfaces = config_lookup(&conf, "interface");

    if (interfaces)
    {
        for (int i = 0; i < MAX_INTERFACES; i++)
        {
            free(cfg->interfaces[i]);
            cfg->interfaces[i] = NULL;
        }
        cfg->interfaces_cnt = 0;
        if (config_setting_is_list(interfaces))
        {
            for (int i = 0; i < config_setting_length(interfaces); i++)
            {
                if (i >= MAX_INTERFACES)
                {
                    break;
                }

                const char* interface = config_setting_get_string_elem(interfaces, i);

                if (!interface)
                {
                    continue;
                }

                if (cfg->interfaces_cnt == 0 && overrides && overrides->interface)
                {
                    cfg->interfaces[cfg->interfaces_cnt] = strdup(overrides->interface);
                }
                else
                {
                    cfg->interfaces[cfg->interfaces_cnt] = strdup(interface);
                }

                cfg->interfaces_cnt++;
            }
        }
        else
        {
            const char* interface;

            if (config_lookup_string(&conf, "interface", &interface) == CONFIG_TRUE)
            {
                if (cfg->interfaces[0])
                {
                    free(cfg->interfaces[0]);
                    cfg->interfaces[0] = NULL;
                }

                if (overrides && overrides->interface)
                {
                    cfg->interfaces[0] = strdup(overrides->interface);
                }
                else
                {
                    cfg->interfaces[0] = strdup(interface);
                }

                cfg->interfaces_cnt = 1;
            }
        }
    }
    else if (overrides && overrides->interface)
    {
        if (cfg->interfaces[0])
        {
            free(cfg->interfaces[0]);
            cfg->interfaces[0] = NULL;
        }

        cfg->interfaces[0] = strdup(overrides->interface);
        cfg->interfaces_cnt = 1;
    }

    // Pin BPF maps.
    int pin_maps;

    if (config_lookup_bool(&conf, "pin_maps", &pin_maps) == CONFIG_TRUE || (overrides && overrides->pin_maps > -1))
    {
        if (overrides && overrides->pin_maps > -1)
        {
            cfg->pin_maps = overrides->pin_maps;
        }
        else
        {
            cfg->pin_maps = pin_maps;
        }
    }

    // Get auto update time.
    int update_time;

    if (config_lookup_int(&conf, "update_time", &update_time) == CONFIG_TRUE || (overrides && overrides->update_time > -1))
    {
        if (overrides && overrides->update_time > -1)
        {
            cfg->update_time = overrides->update_time;
        }
        else
        {
            cfg->update_time = update_time;
        }
    }

    // Get no stats.
    int no_stats;

    if (config_lookup_bool(&conf, "no_stats", &no_stats) == CONFIG_TRUE || (overrides && overrides->no_stats > -1))
    {
        if (overrides && overrides->no_stats > -1)
        {
            cfg->no_stats = overrides->no_stats;
        }
        else
        {
            cfg->no_stats = no_stats;
        }
    }

    // Stats per second.
    int stats_per_second;

    if (config_lookup_bool(&conf, "stats_per_second", &stats_per_second) == CONFIG_TRUE || (overrides && overrides->stats_per_second > -1))
    {
        if (overrides && overrides->stats_per_second > -1)
        {
            cfg->stats_per_second = overrides->stats_per_second;
        }
        else
        {
            cfg->stats_per_second = stats_per_second;
        }
    }

    // Get stdout update time.
    int stdout_update_time;

    if (config_lookup_int(&conf, "stdout_update_time", &stdout_update_time) == CONFIG_TRUE || (overrides && overrides->stdout_update_time > -1))
    {
        if (overrides && overrides->stdout_update_time > -1)
        {
            cfg->stdout_update_time = overrides->stdout_update_time;
        }
        else
        {
            cfg->stdout_update_time = stdout_update_time;
        }
    }

    // Read filters.
    setting = config_lookup(&conf, "filters");

    if (setting && config_setting_is_list(setting))
    {
        cfg->filters_cnt = 0;
        for (int i = 0; i < MAX_FILTERS; i++)
        {
            set_filter_defaults(&cfg->filters[i]);
        }
        for (int i = 0; i < config_setting_length(setting); i++)
        {
            filter_rule_cfg_t* filter = &cfg->filters[i];

            config_setting_t* filter_cfg = config_setting_get_elem(setting, i);

            if (filter_cfg == NULL || config_setting_type(filter_cfg) != CONFIG_TYPE_GROUP)
            {
                fprintf(stderr, "Invalid filter at index #%d.\n", i + 1);
                config_destroy(&conf);
                return EXIT_FAILURE;
            }

            cfg->filters_cnt++;

            // Make sure filter is set.
            filter->set = 1;

            // Enabled.
            int enabled;

            if (config_setting_lookup_bool(filter_cfg, "enabled",  &enabled) == CONFIG_TRUE)
            {
                filter->enabled = enabled;
            }

            // Log.
            int log;

            if (config_setting_lookup_bool(filter_cfg, "log", &log) == CONFIG_TRUE)
            {
                filter->log = log;
            }

            // Action (required).
            int action;

            if (config_setting_lookup_int(filter_cfg, "action", &action) == CONFIG_TRUE)
            {
                filter->action = action;
            }

            // Block time (default 1).
            int block_time;

            if (config_setting_lookup_int(filter_cfg, "block_time", &block_time) == CONFIG_TRUE)
            {
                filter->block_time = block_time;
            }

            // IP PPS (not required).
            s64 ip_pps;

            if (config_setting_lookup_int64(filter_cfg, "ip_pps", &ip_pps) == CONFIG_TRUE)
            {
                filter->ip_pps = ip_pps;
            }

            // IP BPS (not required).
            s64 ip_bps;

            if (config_setting_lookup_int64(filter_cfg, "ip_bps", &ip_bps) == CONFIG_TRUE)
            {
                filter->ip_bps = ip_bps;
            }

            // Flow PPS (not required).
            s64 flow_pps;

            if (config_setting_lookup_int64(filter_cfg, "flow_pps", &flow_pps) == CONFIG_TRUE)
            {
                filter->flow_pps = flow_pps;
            }

            // Flow BPS (not required).
            s64 flow_bps;

            if (config_setting_lookup_int64(filter_cfg, "flow_bps", &flow_bps) == CONFIG_TRUE)
            {
                filter->flow_bps = flow_bps;
            }

            /* IP Options */

            // Source IP (not required).
            const char *sip;

            if (config_setting_lookup_string(filter_cfg, "src_ip", &sip) == CONFIG_TRUE)
            {
                filter->ip.src_ip = strdup(sip);
            }

            // Destination IP (not required).
            const char *dip;

            if (config_setting_lookup_string(filter_cfg, "dst_ip", &dip) == CONFIG_TRUE)
            {
                filter->ip.dst_ip = strdup(dip);
            }

            // Source IP (IPv6) (not required).
            const char *sip6;

            if (config_setting_lookup_string(filter_cfg, "src_ip6", &sip6) == CONFIG_TRUE)
            {
                filter->ip.src_ip6 = strdup(sip6);
            }

            // Destination IP (IPv6) (not required).
            const char *dip6;

            if (config_setting_lookup_string(filter_cfg, "dst_ip6", &dip6) == CONFIG_TRUE)
            {
                filter->ip.dst_ip6 = strdup(dip6);
            }

            // Minimum TTL (not required).
            int min_ttl;

            if (config_setting_lookup_int(filter_cfg, "min_ttl", &min_ttl) == CONFIG_TRUE)
            {
                filter->ip.min_ttl = min_ttl;
            }

            // Maximum TTL (not required).
            int max_ttl;

            if (config_setting_lookup_int(filter_cfg, "max_ttl", &max_ttl) == CONFIG_TRUE)
            {
                filter->ip.max_ttl = max_ttl;
            }

            // Minimum length (not required).
            int min_len;

            if (config_setting_lookup_int(filter_cfg, "min_len", &min_len) == CONFIG_TRUE)
            {
                filter->ip.min_len = min_len;
            }

            // Maximum length (not required).
            int max_len;

            if (config_setting_lookup_int(filter_cfg, "max_len", &max_len) == CONFIG_TRUE)
            {
                filter->ip.max_len = max_len;
            }

            // TOS (not required).
            int tos;

            if (config_setting_lookup_int(filter_cfg, "tos", &tos) == CONFIG_TRUE)
            {
                filter->ip.tos = tos;
            }

            /* TCP options */

            // Enabled.
            int tcp_enabled;

            if (config_setting_lookup_bool(filter_cfg, "tcp_enabled", &tcp_enabled) == CONFIG_TRUE)
            {
                filter->tcp.enabled = tcp_enabled;
            }

            // Source port.
            config_setting_t* tcp_sport = config_setting_lookup(filter_cfg, "tcp_sport");

            if (tcp_sport)
            {
                int type = config_setting_type(tcp_sport);

                if (type == CONFIG_TYPE_STRING)
                {
                    const char* val = config_setting_get_string(tcp_sport);

                    if (val)
                    {
                        filter->tcp.sport = strdup(val);
                    }
                }
                else if (type == CONFIG_TYPE_INT)
                {
                    int val = config_setting_get_int(tcp_sport);

                    char val_str[12];
                    snprintf(val_str, sizeof(val_str), "%d", val);

                    filter->tcp.sport = strdup(val_str);
                }
            }

            // Destination port.
            config_setting_t* tcp_dport = config_setting_lookup(filter_cfg, "tcp_dport");

            if (tcp_dport)
            {
                int type = config_setting_type(tcp_dport);

                if (type == CONFIG_TYPE_STRING)
                {
                    const char* val = config_setting_get_string(tcp_dport);

                    if (val)
                    {
                        filter->tcp.dport = strdup(val);
                    }
                }
                else if (type == CONFIG_TYPE_INT)
                {
                    int val = config_setting_get_int(tcp_dport);

                    char val_str[12];
                    snprintf(val_str, sizeof(val_str), "%d", val);

                    filter->tcp.dport = strdup(val_str);
                }
            }

            // URG flag.
            int tcp_urg;

            if (config_setting_lookup_bool(filter_cfg, "tcp_urg", &tcp_urg) == CONFIG_TRUE)
            {
                filter->tcp.urg = tcp_urg;
            }

            // ACK flag.
            int tcp_ack;

            if (config_setting_lookup_bool(filter_cfg, "tcp_ack", &tcp_ack) == CONFIG_TRUE)
            {
                filter->tcp.ack = tcp_ack;
            }
            
            // RST flag.
            int tcp_rst;

            if (config_setting_lookup_bool(filter_cfg, "tcp_rst", &tcp_rst) == CONFIG_TRUE)
            {
                filter->tcp.rst = tcp_rst;
            }

            // PSH flag.
            int tcp_psh;

            if (config_setting_lookup_bool(filter_cfg, "tcp_psh", &tcp_psh) == CONFIG_TRUE)
            {
                filter->tcp.psh = tcp_psh;
            }

            // SYN flag.
            int tcp_syn;

            if (config_setting_lookup_bool(filter_cfg, "tcp_syn", &tcp_syn) == CONFIG_TRUE)
            {
                filter->tcp.syn = tcp_syn;
            }

            // FIN flag.
            int tcp_fin;

            if (config_setting_lookup_bool(filter_cfg, "tcp_fin", &tcp_fin) == CONFIG_TRUE)
            {
                filter->tcp.fin = tcp_fin;
            }

            // ECE flag.
            int tcp_ece;

            if (config_setting_lookup_bool(filter_cfg, "tcp_ece", &tcp_ece) == CONFIG_TRUE)
            {
                filter->tcp.ece = tcp_ece;
            }

            // CWR flag.
            int tcp_cwr;

            if (config_setting_lookup_bool(filter_cfg, "tcp_cwr", &tcp_cwr) == CONFIG_TRUE)
            {
                filter->tcp.cwr = tcp_cwr;
            }

            /* UDP options */

            // Enabled.
            int udp_enabled;

            if (config_setting_lookup_bool(filter_cfg, "udp_enabled", &udp_enabled) == CONFIG_TRUE)
            {
                filter->udp.enabled = udp_enabled;
            }

            // Source port.
            config_setting_t* udp_sport = config_setting_lookup(filter_cfg, "udp_sport");

            if (udp_sport)
            {
                int type = config_setting_type(udp_sport);

                if (type == CONFIG_TYPE_STRING)
                {
                    const char* val = config_setting_get_string(udp_sport);

                    if (val)
                    {
                        filter->udp.sport = strdup(val);
                    }
                }
                else if (type == CONFIG_TYPE_INT)
                {
                    int val = config_setting_get_int(udp_sport);

                    char val_str[12];
                    snprintf(val_str, sizeof(val_str), "%d", val);

                    filter->udp.sport = strdup(val_str);
                }
            }

            // Destination port.
            config_setting_t* udp_dport = config_setting_lookup(filter_cfg, "udp_dport");

            if (udp_dport)
            {
                int type = config_setting_type(udp_dport);

                if (type == CONFIG_TYPE_STRING)
                {
                    const char* val = config_setting_get_string(udp_dport);

                    if (val)
                    {
                        filter->udp.dport = strdup(val);
                    }
                }
                else if (type == CONFIG_TYPE_INT)
                {
                    int val = config_setting_get_int(udp_dport);

                    char val_str[12];
                    snprintf(val_str, sizeof(val_str), "%d", val);

                    filter->udp.dport = strdup(val_str);
                }
            }
            
            /* ICMP options */

            // Enabled.
            int icmp_enabled;

            if (config_setting_lookup_bool(filter_cfg, "icmp_enabled", &icmp_enabled) == CONFIG_TRUE)
            {
                filter->icmp.enabled = icmp_enabled;
            }

            // ICMP code.
            int icmp_code;

            if (config_setting_lookup_int(filter_cfg, "icmp_code", &icmp_code) == CONFIG_TRUE)
            {
                filter->icmp.code = icmp_code;
            }

            // ICMP type.
            int icmp_type;

            if (config_setting_lookup_int(filter_cfg, "icmp_type", &icmp_type) == CONFIG_TRUE)
            {
                filter->icmp.type = icmp_type;
            }
        }
    }

    // Read IP range drops.
    setting = config_lookup(&conf, "ip_drop_ranges");

    if (setting && config_setting_is_list(setting))
    {
        cfg->drop_ranges_cnt = 0;
        for (int i = 0; i < MAX_IP_RANGES; i++)
        {
            free(cfg->drop_ranges[i]);
            cfg->drop_ranges[i] = NULL;
        }
        for (int i = 0; i < config_setting_length(setting) && i < MAX_IP_RANGES; i++)
        {
            const char* new_range = config_setting_get_string_elem(setting, i);

            if (!new_range)
            {
                continue;
            }

            cfg->drop_ranges[i] = strdup(new_range);

            cfg->drop_ranges_cnt++;
        }
    }

    config_destroy(&conf);

    if (cfg->update_time < 0 || cfg->stdout_update_time <= 0 || cfg->stdout_update_time > 3600000)
    {
        fprintf(stderr, "Invalid update interval. stdout_update_time must be 1..3600000 ms.\n");
        return EXIT_FAILURE;
    }
    for (int i = 0; i < cfg->filters_cnt; i++)
    {
        filter_rule_cfg_t *filter = &cfg->filters[i];
        if (validate_filter(filter) != 0)
        {
            fprintf(stderr, "Invalid address, port, or scalar in filter #%d.\n", i + 1);
            return EXIT_FAILURE;
        }
    }
    for (int i = 0; i < MAX_IP_RANGES; i++)
    {
        if (cfg->drop_ranges[i] && !parse_ip_range(cfg->drop_ranges[i]).success)
        {
            fprintf(stderr, "Invalid IP drop range: %s\n", cfg->drop_ranges[i]);
            return EXIT_FAILURE;
        }
    }
    return EXIT_SUCCESS;
}

int validate_filter(const filter_rule_cfg_t *filter)
{
    struct in6_addr addr;
    if ((filter->ip.src_ip && !parse_ip_range(filter->ip.src_ip).success) ||
        (filter->ip.dst_ip && !parse_ip_range(filter->ip.dst_ip).success) ||
        (filter->ip.src_ip6 && inet_pton(AF_INET6, filter->ip.src_ip6, &addr) != 1) ||
        (filter->ip.dst_ip6 && inet_pton(AF_INET6, filter->ip.dst_ip6, &addr) != 1) ||
        (filter->tcp.sport && !parse_port_range(filter->tcp.sport).success) ||
        (filter->tcp.dport && !parse_port_range(filter->tcp.dport).success) ||
        (filter->udp.sport && !parse_port_range(filter->udp.sport).success) ||
        (filter->udp.dport && !parse_port_range(filter->udp.dport).success) ||
        filter->action < -1 || filter->action > 1 ||
        filter->enabled < -1 || filter->enabled > 1 ||
        filter->log < -1 || filter->log > 1 ||
        filter->tcp.enabled < -1 || filter->tcp.enabled > 1 ||
        filter->udp.enabled < -1 || filter->udp.enabled > 1 ||
        filter->icmp.enabled < -1 || filter->icmp.enabled > 1 ||
        filter->tcp.urg < -1 || filter->tcp.urg > 1 ||
        filter->tcp.ack < -1 || filter->tcp.ack > 1 ||
        filter->tcp.rst < -1 || filter->tcp.rst > 1 ||
        filter->tcp.psh < -1 || filter->tcp.psh > 1 ||
        filter->tcp.syn < -1 || filter->tcp.syn > 1 ||
        filter->tcp.fin < -1 || filter->tcp.fin > 1 ||
        filter->tcp.ece < -1 || filter->tcp.ece > 1 ||
        filter->tcp.cwr < -1 || filter->tcp.cwr > 1 ||
        filter->block_time < -1 || filter->block_time > 65535 ||
        filter->ip_pps < -1 || filter->ip_bps < -1 ||
        filter->flow_pps < -1 || filter->flow_bps < -1 ||
        filter->ip.min_ttl < -1 || filter->ip.min_ttl > 255 ||
        filter->ip.max_ttl < -1 || filter->ip.max_ttl > 255 ||
        filter->ip.tos < -1 || filter->ip.tos > 255 ||
        filter->ip.min_len < -1 || filter->ip.min_len > 65535 ||
        filter->ip.max_len < -1 || filter->ip.max_len > 65535 ||
        filter->icmp.code < -1 || filter->icmp.code > 255 ||
        filter->icmp.type < -1 || filter->icmp.type > 255 ||
        (filter->ip.min_ttl > -1 && filter->ip.max_ttl > -1 && filter->ip.min_ttl > filter->ip.max_ttl) ||
        (filter->ip.min_len > -1 && filter->ip.max_len > -1 && filter->ip.min_len > filter->ip.max_len))
    {
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

/**
 * Saves config to file system.
 * 
 * @param cfg A pointer to the config.
 * @param file_path The file path to store the config into.
 * 
 * @param return 0 on success or 1 on failure.
 */
int save_cfg(config__t* cfg, const char* file_path)
{
    config_t conf;
    config_setting_t *root, *setting;

    FILE* file;

    config_init(&conf);
    root = config_root_setting(&conf);

    // Add verbose.
    setting = config_setting_add(root, "verbose", CONFIG_TYPE_INT);
    config_setting_set_int(setting, cfg->verbose);

    // Add log file.
    setting = config_setting_add(root, "log_file", CONFIG_TYPE_STRING);
    config_setting_set_string(setting, cfg->log_file ? cfg->log_file : "");

    // Add interface(s).
    if (cfg->interfaces_cnt > 0)
    {
        if (cfg->interfaces_cnt > 1)
        {
            setting = config_setting_add(root, "interface", CONFIG_TYPE_LIST);

            for (int i = 0; i < cfg->interfaces_cnt; i++)
            {
                const char* interface = cfg->interfaces[i];

                if (!interface)
                {
                    continue;
                }

                config_setting_t* setting_interface = config_setting_add(setting, NULL, CONFIG_TYPE_STRING);
                config_setting_set_string(setting_interface, interface);
            }
        }
        else
        {
            const char* interface = cfg->interfaces[0];

            if (interface)
            {
                setting = config_setting_add(root, "interface", CONFIG_TYPE_STRING);
                config_setting_set_string(setting, interface);
            }
        }
    }

    // Add pin maps.
    setting = config_setting_add(root, "pin_maps", CONFIG_TYPE_BOOL);
    config_setting_set_bool(setting, cfg->pin_maps);

    // Add update time.
    setting = config_setting_add(root, "update_time", CONFIG_TYPE_INT);
    config_setting_set_int(setting, cfg->update_time);

    // Add no stats.
    setting = config_setting_add(root, "no_stats", CONFIG_TYPE_BOOL);
    config_setting_set_bool(setting, cfg->no_stats);

    // Add stats per second.
    setting = config_setting_add(root, "stats_per_second", CONFIG_TYPE_BOOL);
    config_setting_set_bool(setting, cfg->stats_per_second);

    // Add stdout update time.
    setting = config_setting_add(root, "stdout_update_time", CONFIG_TYPE_INT);
    config_setting_set_int(setting, cfg->stdout_update_time);

    // Add filters.
    config_setting_t* filters = config_setting_add(root, "filters", CONFIG_TYPE_LIST);

    if (filters)
    {
        for (int i = 0; i < MAX_FILTERS; i++)
        {
            filter_rule_cfg_t* filter = &cfg->filters[i];

            if (!filter->set)
            {
                continue;
            }

            config_setting_t* filter_cfg = config_setting_add(filters, NULL, CONFIG_TYPE_GROUP);

            if (filter_cfg)
            {
                // Add enabled setting.
                if (filter->enabled > -1)
                {
                    config_setting_t* enabled = config_setting_add(filter_cfg, "enabled", CONFIG_TYPE_BOOL);
                    config_setting_set_bool(enabled, filter->enabled);
                }

                // Add log setting.
                if (filter->log > -1)
                {
                    config_setting_t* log = config_setting_add(filter_cfg, "log", CONFIG_TYPE_BOOL);
                    config_setting_set_bool(log, filter->log);
                }

                // Add action setting.
                if (filter->action > -1)
                {
                    config_setting_t* action = config_setting_add(filter_cfg, "action", CONFIG_TYPE_INT);
                    config_setting_set_int(action, filter->action);
                }

                // Add block time.
                if (filter->block_time > -1)
                {
                    config_setting_t* block_time = config_setting_add(filter_cfg, "block_time", CONFIG_TYPE_INT);
                    config_setting_set_int(block_time, filter->block_time);
                }

                // Add IP PPS.
                if (filter->ip_pps > -1)
                {
                    config_setting_t* pps = config_setting_add(filter_cfg, "ip_pps", CONFIG_TYPE_INT64);
                    config_setting_set_int64(pps, filter->ip_pps);
                }

                // Add IP BPS.
                if (filter->ip_bps > -1)
                {
                    config_setting_t* bps = config_setting_add(filter_cfg, "ip_bps", CONFIG_TYPE_INT64);
                    config_setting_set_int64(bps, filter->ip_bps);
                }

                // Add flow PPS.
                if (filter->flow_pps > -1)
                {
                    config_setting_t* pps = config_setting_add(filter_cfg, "flow_pps", CONFIG_TYPE_INT64);
                    config_setting_set_int64(pps, filter->flow_pps);
                }

                // Add flow BPS.
                if (filter->flow_bps > -1)
                {
                    config_setting_t* bps = config_setting_add(filter_cfg, "flow_bps", CONFIG_TYPE_INT64);
                    config_setting_set_int64(bps, filter->flow_bps);
                }

                // Add source IPv4.
                if (filter->ip.src_ip)
                {
                    config_setting_t* src_ip = config_setting_add(filter_cfg, "src_ip", CONFIG_TYPE_STRING);
                    config_setting_set_string(src_ip, filter->ip.src_ip);
                }

                // Add destination IPv4.
                if (filter->ip.dst_ip)
                {
                    config_setting_t* dst_ip = config_setting_add(filter_cfg, "dst_ip", CONFIG_TYPE_STRING);
                    config_setting_set_string(dst_ip, filter->ip.dst_ip);
                }

                // Add source IPv6.
                if (filter->ip.src_ip6)
                {
                    config_setting_t* src_ip6 = config_setting_add(filter_cfg, "src_ip6", CONFIG_TYPE_STRING);
                    config_setting_set_string(src_ip6, filter->ip.src_ip6);
                }

                // Add source IPv6.
                if (filter->ip.dst_ip6)
                {
                    config_setting_t* dst_ip6 = config_setting_add(filter_cfg, "dst_ip6", CONFIG_TYPE_STRING);
                    config_setting_set_string(dst_ip6, filter->ip.dst_ip6);
                }

                // Add minimum TTL.
                if (filter->ip.min_ttl > -1)
                {
                    config_setting_t* min_ttl = config_setting_add(filter_cfg, "min_ttl", CONFIG_TYPE_INT);
                    config_setting_set_int(min_ttl, filter->ip.min_ttl);
                }

                // Add maximum TTL.
                if (filter->ip.max_ttl > -1)
                {
                    config_setting_t* max_ttl = config_setting_add(filter_cfg, "max_ttl", CONFIG_TYPE_INT);
                    config_setting_set_int(max_ttl, filter->ip.max_ttl);
                }

                // Add minimum length.
                if (filter->ip.min_len > -1)
                {
                    config_setting_t* min_len = config_setting_add(filter_cfg, "min_len", CONFIG_TYPE_INT);
                    config_setting_set_int(min_len, filter->ip.min_len);
                }

                // Add maximum length.
                if (filter->ip.max_len > -1)
                {
                    config_setting_t* max_len = config_setting_add(filter_cfg, "max_len", CONFIG_TYPE_INT);
                    config_setting_set_int(max_len, filter->ip.max_len);
                }

                // Add ToS.
                if (filter->ip.tos > -1)
                {
                    config_setting_t* tos = config_setting_add(filter_cfg, "tos", CONFIG_TYPE_INT);
                    config_setting_set_int(tos, filter->ip.tos);
                }


                // Add TCP enabled.
                if (filter->tcp.enabled > -1)
                {
                    config_setting_t* tcp_enabled = config_setting_add(filter_cfg, "tcp_enabled", CONFIG_TYPE_BOOL);
                    config_setting_set_bool(tcp_enabled, filter->tcp.enabled);
                }

                // Add TCP source port.
                if (filter->tcp.sport)
                {
                    config_setting_t* tcp_sport = config_setting_add(filter_cfg, "tcp_sport", CONFIG_TYPE_STRING);
                    config_setting_set_string(tcp_sport, filter->tcp.sport);
                }

                // Add TCP destination port.
                if (filter->tcp.dport)
                {
                    config_setting_t* tcp_dport = config_setting_add(filter_cfg, "tcp_dport", CONFIG_TYPE_STRING);
                    config_setting_set_string(tcp_dport, filter->tcp.dport);
                }

                // Add TCP URG flag.
                if (filter->tcp.urg > -1)
                {
                    config_setting_t* tcp_urg = config_setting_add(filter_cfg, "tcp_urg", CONFIG_TYPE_BOOL);
                    config_setting_set_bool(tcp_urg, filter->tcp.urg);
                }

                // Add TCP ACK flag.
                if (filter->tcp.ack > -1)
                {
                    config_setting_t* tcp_ack = config_setting_add(filter_cfg, "tcp_ack", CONFIG_TYPE_BOOL);
                    config_setting_set_bool(tcp_ack, filter->tcp.ack);
                }

                // Add TCP RST flag.
                if (filter->tcp.rst > -1)
                {
                    config_setting_t* tcp_rst = config_setting_add(filter_cfg, "tcp_rst", CONFIG_TYPE_BOOL);
                    config_setting_set_bool(tcp_rst, filter->tcp.rst);
                }

                // Add TCP PSH flag.
                if (filter->tcp.psh > -1)
                {
                    config_setting_t* tcp_psh = config_setting_add(filter_cfg, "tcp_psh", CONFIG_TYPE_BOOL);
                    config_setting_set_bool(tcp_psh, filter->tcp.psh);
                }

                // Add TCP SYN flag.
                if (filter->tcp.syn > -1)
                {
                    config_setting_t* tcp_syn = config_setting_add(filter_cfg, "tcp_syn", CONFIG_TYPE_BOOL);
                    config_setting_set_bool(tcp_syn, filter->tcp.syn);
                }

                // Add TCP FIN flag.
                if (filter->tcp.fin > -1)
                {
                    config_setting_t* tcp_fin = config_setting_add(filter_cfg, "tcp_fin", CONFIG_TYPE_BOOL);
                    config_setting_set_bool(tcp_fin, filter->tcp.fin);
                }

                // Add TCP ECE flag.
                if (filter->tcp.ece > -1)
                {
                    config_setting_t* tcp_ece = config_setting_add(filter_cfg, "tcp_ece", CONFIG_TYPE_BOOL);
                    config_setting_set_bool(tcp_ece, filter->tcp.ece);
                }

                // Add TCP CWR flag.
                if (filter->tcp.cwr > -1)
                {
                    config_setting_t* tcp_cwr = config_setting_add(filter_cfg, "tcp_cwr", CONFIG_TYPE_BOOL);
                    config_setting_set_bool(tcp_cwr, filter->tcp.cwr);
                }

                // Add UDP enabled.
                if (filter->udp.enabled > -1)
                {
                    config_setting_t* udp_enabled = config_setting_add(filter_cfg, "udp_enabled", CONFIG_TYPE_BOOL);
                    config_setting_set_bool(udp_enabled, filter->udp.enabled);
                }

                // Add UDP source port.
                if (filter->udp.sport)
                {
                    config_setting_t* udp_sport = config_setting_add(filter_cfg, "udp_sport", CONFIG_TYPE_STRING);
                    config_setting_set_string(udp_sport, filter->udp.sport);
                }

                // Add UDP destination port.
                if (filter->udp.dport)
                {
                    config_setting_t* udp_dport = config_setting_add(filter_cfg, "udp_dport", CONFIG_TYPE_STRING);
                    config_setting_set_string(udp_dport, filter->udp.dport);
                }

                // Add ICMP enabled.
                if (filter->icmp.enabled > -1)
                {
                    config_setting_t* icmp_enabled = config_setting_add(filter_cfg, "icmp_enabled", CONFIG_TYPE_BOOL);
                    config_setting_set_bool(icmp_enabled, filter->icmp.enabled);
                }

                // Add ICMP code.
                if (filter->icmp.code > -1)
                {
                    config_setting_t* icmp_code = config_setting_add(filter_cfg, "icmp_code", CONFIG_TYPE_INT);
                    config_setting_set_int(icmp_code, filter->icmp.code);
                }

                // Add ICMP type.
                if (filter->icmp.type > -1)
                {
                    config_setting_t* icmp_type = config_setting_add(filter_cfg, "icmp_type", CONFIG_TYPE_INT);
                    config_setting_set_int(icmp_type, filter->icmp.type);
                }
            }
        }
    }

    // Add IP ranges.
    config_setting_t* ip_drop_ranges = config_setting_add(root, "ip_drop_ranges", CONFIG_TYPE_LIST);

    if (ip_drop_ranges)
    {
        for (int i = 0; i < MAX_IP_RANGES; i++)
        {
            const char* range = cfg->drop_ranges[i];

            if (range)
            {
                config_setting_t* elem = config_setting_add(ip_drop_ranges, NULL, CONFIG_TYPE_STRING);

                if (elem)
                {
                    config_setting_set_string(elem, range);
                }
            }
        }
    }

    // Write config to file.
    file = fopen(file_path, "w");

    if (!file)
    {
        config_destroy(&conf);

        return 1;
    }

    config_write(&conf, file);

    int failed = ferror(file);
    if (fclose(file) != 0)
    {
        failed = 1;
    }
    config_destroy(&conf);

    return failed;
}

/**
 * Sets the default values for a filter.
 * 
 * @param filter A pointer to the filter.
 * 
 * @return void
 */
void set_filter_defaults(filter_rule_cfg_t* filter)
{
    filter->set = 0;
    filter->enabled = 1;

    filter->log = 0;

    filter->action = 1;
    filter->block_time = 1;

    filter->ip_pps = -1;
    filter->ip_bps = -1;
    filter->flow_pps = -1;
    filter->flow_bps = -1;

    if (filter->ip.src_ip)
    {
        free(filter->ip.src_ip);

        filter->ip.src_ip = NULL;
    }

    if (filter->ip.dst_ip)
    {
        free(filter->ip.dst_ip);

        filter->ip.dst_ip = NULL;
    }

    if (filter->ip.src_ip6)
    {
        free(filter->ip.src_ip6);

        filter->ip.src_ip6 = NULL;
    }

    if (filter->ip.dst_ip6)
    {
        free(filter->ip.dst_ip6);

        filter->ip.dst_ip6 = NULL;
    }

    filter->ip.min_ttl = -1;
    filter->ip.max_ttl = -1;

    filter->ip.min_len = -1;
    filter->ip.max_len = -1;

    filter->ip.tos = -1;

    filter->tcp.enabled = -1;

    if (filter->tcp.sport)
    {
        free(filter->tcp.sport);

        filter->tcp.sport = NULL;
    }

    if (filter->tcp.dport)
    {
        free(filter->tcp.dport);

        filter->tcp.dport = NULL;
    }

    filter->tcp.urg = -1;
    filter->tcp.ack = -1;
    filter->tcp.rst = -1;
    filter->tcp.psh = -1;
    filter->tcp.syn = -1;
    filter->tcp.fin = -1;
    filter->tcp.ece = -1;
    filter->tcp.cwr = -1;

    filter->udp.enabled = -1;
    
    if (filter->udp.sport)
    {
        free(filter->udp.sport);

        filter->udp.sport = NULL;
    }

    if (filter->udp.dport)
    {
        free(filter->udp.dport);

        filter->udp.dport = NULL;
    }

    filter->icmp.enabled = -1;
    filter->icmp.code = -1;
    filter->icmp.type = -1;
}

/**
 * Sets the config structure's default values.
 * 
 * @param cfg A pointer to the config structure.
 * 
 * @return void
 */
void set_cfg_defaults(config__t* cfg)
{
    cfg->verbose = 2;
    cfg->update_time = 0;
    cfg->pin_maps = 1;
    cfg->no_stats = 0;
    cfg->stats_per_second = 0;
    cfg->stdout_update_time = 1000;

    if (cfg->log_file)
    {
        free(cfg->log_file);

        cfg->log_file = NULL;
    }

    cfg->log_file = strdup("/var/log/xdpfw.log");

    cfg->interfaces_cnt = 0;

    for (int i = 0; i < MAX_INTERFACES; i++)
    {
        char* interface = cfg->interfaces[i];

        if (!interface)
        {
            continue;
        }

        free(interface);

        cfg->interfaces[i] = NULL;
    }

    cfg->filters_cnt = 0;

    for (int i = 0; i < MAX_FILTERS; i++)
    {
        filter_rule_cfg_t* filter = &cfg->filters[i];

        set_filter_defaults(filter);
    }

    cfg->drop_ranges_cnt = 0;

    for (int i = 0; i < MAX_IP_RANGES; i++)
    {
        char* drop_range = cfg->drop_ranges[i];

        if (!drop_range)
        {
            continue;
        }

        free(drop_range);

        cfg->drop_ranges[i] = NULL;
    }
}

void free_cfg(config__t *cfg)
{
    free(cfg->log_file);
    for (int i = 0; i < MAX_INTERFACES; i++)
    {
        free(cfg->interfaces[i]);
    }
    for (int i = 0; i < MAX_FILTERS; i++)
    {
        set_filter_defaults(&cfg->filters[i]);
    }
    for (int i = 0; i < MAX_IP_RANGES; i++)
    {
        free(cfg->drop_ranges[i]);
    }
    memset(cfg, 0, sizeof(*cfg));
}

/**
 * Prints a filter rule.
 * 
 * @param filter A pointer to the filter rule.
 * @param idx The current index.
 * 
 * @return void
 */
void print_filter(filter_rule_cfg_t* filter, int idx)
{
    printf("\tFilter #%d\n", idx);
    printf("\t\tEnabled => %d\n", filter->enabled);
    printf("\t\tLog => %d\n\n", filter->log);

    printf("\t\tAction => %d (0 = Block, 1 = Allow)\n", filter->action);
    printf("\t\tBlock Time => %d\n\n", filter->block_time);

    printf("\t\tIP PPS => %lld\n", filter->ip_pps);
    printf("\t\tIP BPS => %lld\n", filter->ip_bps);

    printf("\t\tFlow PPS => %lld\n", filter->flow_pps);
    printf("\t\tFlow BPS => %lld\n", filter->flow_bps);

    printf("\t\tMin Packet Length => %d\n", filter->ip.min_len);
    printf("\t\tMax Packet Length => %d\n\n", filter->ip.max_len);

    // IP Options.
    const char* src_ip = "N/A";

    if (filter->ip.src_ip)
    {
        src_ip = filter->ip.src_ip;
    }

    const char* dst_ip = "N/A";

    if (filter->ip.dst_ip)
    {
        dst_ip = filter->ip.dst_ip;
    }

    const char* src_ip6 = "N/A";

    if (filter->ip.src_ip6)
    {
        src_ip6 = filter->ip.src_ip6;
    }

    const char* dst_ip6 = "N/A";

    if (filter->ip.dst_ip6)
    {
        dst_ip6 = filter->ip.dst_ip6;
    }

    printf("\t\tIP Options\n");

    printf("\t\t\tSource IPv4 => %s\n", src_ip);
    printf("\t\t\tDestination IPv4 => %s\n", dst_ip);
    printf("\t\t\tSource IPv6 => %s\n", src_ip6);
    printf("\t\t\tDestination IPv6 => %s\n", dst_ip6);

    printf("\t\t\tMin TTL => %d\n", filter->ip.min_ttl);
    printf("\t\t\tMax TTL => %d\n", filter->ip.max_ttl);

    printf("\t\t\tTOS => %d\n\n", filter->ip.tos);

    // TCP Options.
    const char* tcp_sport = "N/A";

    if (filter->tcp.sport)
    {
        tcp_sport = filter->tcp.sport;
    }

    const char* tcp_dport = "N/A";

    if (filter->tcp.dport)
    {
        tcp_dport = filter->tcp.dport;
    }

    printf("\t\tTCP Options\n");

    printf("\t\t\tTCP Enabled => %d\n", filter->tcp.enabled);
    printf("\t\t\tTCP Source Port => %s\n", tcp_sport);
    printf("\t\t\tTCP Destination Port => %s\n", tcp_dport);
    printf("\t\t\tTCP URG Flag => %d\n", filter->tcp.urg);
    printf("\t\t\tTCP ACK Flag => %d\n", filter->tcp.ack);
    printf("\t\t\tTCP RST Flag => %d\n", filter->tcp.rst);
    printf("\t\t\tTCP PSH Flag => %d\n", filter->tcp.psh);
    printf("\t\t\tTCP SYN Flag => %d\n", filter->tcp.syn);
    printf("\t\t\tTCP FIN Flag => %d\n", filter->tcp.fin);
    printf("\t\t\tTCP ECE Flag => %d\n", filter->tcp.ece);
    printf("\t\t\tTCP CWR Flag => %d\n\n", filter->tcp.cwr);

    // UDP Options.
    const char* udp_sport = "N/A";

    if (filter->udp.sport)
    {
        udp_sport = filter->udp.sport;
    }

    const char* udp_dport = "N/A";

    if (filter->udp.dport)
    {
        udp_dport = filter->udp.dport;
    }

    printf("\t\tUDP Options\n");

    printf("\t\t\tUDP Enabled => %d\n", filter->udp.enabled);
    printf("\t\t\tUDP Source Port => %s\n", udp_sport);
    printf("\t\t\tUDP Destination Port => %s\n\n", udp_dport);

    // ICMP Options.
    printf("\t\tICMP Options\n");

    printf("\t\t\tICMP Enabled => %d\n", filter->icmp.enabled);
    printf("\t\t\tICMP Code => %d\n", filter->icmp.code);
    printf("\t\t\tICMP Type => %d\n", filter->icmp.type);
}

/**
 * Prints config settings.
 * 
 * @param cfg A pointer to the config structure.
 * 
 * @return void
 */
void print_cfg(config__t* cfg)
{
    const char* log_file = "N/A";

    if (cfg->log_file != NULL)
    {
        log_file = cfg->log_file;
    }

    printf("Printing config...\n");
    printf("General Settings\n");
    printf("\tVerbose => %d\n", cfg->verbose);
    printf("\tLog File => %s\n", log_file);
    printf("\tPin BPF Maps => %d\n", cfg->pin_maps);
    printf("\tUpdate Time => %d\n", cfg->update_time);
    printf("\tNo Stats => %d\n", cfg->no_stats);
    printf("\tStats Per Second => %d\n", cfg->stats_per_second);
    printf("\tStdout Update Time => %d\n\n", cfg->stdout_update_time);

    printf("Interfaces\n");
    
    if (cfg->interfaces_cnt > 0)
    {
        for (int i = 0; i < cfg->interfaces_cnt; i++)
        {
            const char* interface = cfg->interfaces[i];
    
            if (!interface)
            {
                continue;
            }

            printf("\t- %s\n", interface);
        }

        printf("\n");
    }
    else
    {
        printf("\t- None\n\n");
    }

    printf("Filters\n");

    if (cfg->filters_cnt > 0)
    {
        for (int i = 0; i < cfg->filters_cnt; i++)
        {
            filter_rule_cfg_t *filter = &cfg->filters[i];
    
            if (!filter->set)
            {
                break;
            }
    
            print_filter(filter, i + 1);
    
            printf("\n\n");
        }

        printf("\n");
    }
    else
    {
        printf("\t- None\n\n");
    }
    
    printf("IP Drop Ranges\n");

    if (cfg->drop_ranges_cnt > 0)
    {
        for (int i = 0; i < cfg->drop_ranges_cnt; i++)
        {
            const char* range = cfg->drop_ranges[i];
    
            if (!range)
            {
                continue;
            }

            printf("\t- %s\n", range);
        }
    }
    else
    {
        printf("\t- None\n");
    }
}

/**
 * Retrieves next available filter index.
 * 
 * @param cfg A pointer to the config structure.
 * 
 * @return The next available index or -1 if there are no available indexes.
 */
int get_next_filter_idx(config__t* cfg)
{
    for (int i = 0; i < MAX_FILTERS; i++)
    {
        filter_rule_cfg_t* filter = &cfg->filters[i];

        if (filter->set)
        {
            continue;
        }

        return i;
    }

    return -1;
}

/**
 * Retrieves the next available IP drop range index.
 * 
 * @param cfg A pointer to the config structure.
 * 
 * @return The next available index or -1 if there are no available indexes.
 */
int get_next_ip_drop_range_idx(config__t* cfg)
{
    for (int i = 0; i < MAX_IP_RANGES; i++)
    {
        const char* range = cfg->drop_ranges[i];

        if (range)
        {
            continue;
        }

        return i;
    }

    return -1;
}
