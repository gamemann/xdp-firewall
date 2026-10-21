#include <common/all.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <loader/utils/xdp.h>
#include <loader/utils/config.h>

#include <rule_add/utils/cli.h>

// These are required due to being extern with Loader.
// To Do: Figure out a way to not require the below without requiring separate object files.
int cont = 0;
int doing_stats = 0;

int main(int argc, char *argv[])
{
    int ret;

    // Parse command line.
    cli_t cli = {0};
    cli.cfg_file = CONFIG_DEFAULT_PATH;

    // We need to set integers for dynamic filters to -1 since we consider -1 as 'unset'.
    cli.enabled = -1;
    cli.log = -1;

    cli.action = -1;
    cli.block_time = -1;

    cli.ip_pps = -1;
    cli.ip_bps = -1;

    cli.flow_pps = -1;
    cli.flow_bps = -1;

    cli.min_ttl = -1;
    cli.max_ttl = -1;
    cli.min_len = -1;
    cli.max_len = -1;
    cli.tos = -1;

    cli.tcp_enabled = -1;
    cli.tcp_urg = -1;
    cli.tcp_ack = -1;
    cli.tcp_rst = -1;
    cli.tcp_psh = -1;
    cli.tcp_syn = -1;
    cli.tcp_fin = -1;
    cli.tcp_ece = -1;
    cli.tcp_cwr = -1;

    cli.udp_enabled = -1;

    cli.icmp_enabled = -1;
    cli.icmp_code = -1;
    cli.icmp_type = -1;

    parse_cli(&cli, argc, argv);

    if (!cli.help)
    {
        printf("Parsed command line...\n");
    }
    else
    {
        printf("Usage: xdpfw-add [OPTIONS]\n\n");

        printf("OPTIONS:\n");
        printf("  -c, --cfg         The path to the config file (default /etc/xdpfw/xdpfw.conf).\n");
        printf("  -s, --save        Saves the new config to file system.\n");
        printf("  -m, --mode        The mode to use (0 = filters, 1 = IPv4 range drop, 2 = IP block map).\n");
        printf("  -i, --idx         The filters index to update when using filters mode (0) (index starts from 1; retrieve index using xdpfw -l).\n");
        printf("  -d, --ip          The IP range or single IP to add (for modes 1 and 2).\n");
        printf("  -v, --v6          If set, parses IP address as IPv6 when adding to block map (for mode 2).\n");
        printf("  -e, --expires     How long to block the IP for in seconds (for mode 2).\n\n");

        printf("Filter Mode Options:\n");
        printf("  --enabled         Enables or disables the dynamic filter.\n");
        printf("  --action          The action when a packet matches (0 = drop, 1 = allow).\n");
        printf("  --log             Enables or disables logging for this filter.\n");
        printf("  --block-time      How long to add the source IP to the block list for if matched and the action is drop (0 = no time).\n\n");

        printf("  --sip             The source IPv4 address (with CIDR support).\n");
        printf("  --dip             The destination IPv4 address (with CIDR support).\n");
        printf("  --sip6            The source IPv6 address.\n");
        printf("  --dip6            The destination IPv6 address.\n");
        printf("  --min-ttl         The minimum IP TTL to match.\n");
        printf("  --max-ttl         The maximum IP TTL to match.\n");
        printf("  --min-len         The minimum packet length to match.\n");
        printf("  --max-len         The maximum packet length to match.\n");
        printf("  --tos             The IP Type of Service to match.\n\n");

        printf("  --ip-pps          The minimum IP-level packet rate (per second) to match.\n");
        printf("  --ip-bps          The minimum IP-level byte rate (per second) to match.\n");
        printf("  --flow-pps        The minimum flow-level packet rate (per second) to match.\n");
        printf("  --flow-bps        The minimum flow-level byte rate (per second) to match.\n\n");
        
        printf("  --tcp             Enable or disables matching on the TCP protocol.\n");
        printf("  --tsport          The TCP source port to match on.\n");
        printf("  --tdport          The TCP destination port to match on.\n");
        printf("  --urg             Enables or disables matching on TCP URG flag.\n");
        printf("  --ack             Enables or disables matching on TCP ACK flag.\n");
        printf("  --rst             Enables or disables matching on TCP RST flag.\n");
        printf("  --psh             Enables or disables matching on TCP PSH flag.\n");
        printf("  --syn             Enables or disables matching on TCP SYN flag.\n");
        printf("  --fin             Enables or disables matching on TCP FIN flag.\n");
        printf("  --ece             Enables or disables matching on TCP ECE flag.\n");
        printf("  --cwr             Enables or disables matching on TCP CWR flag.\n\n");

        printf("  --udp             Enable or disables matching on the UDP protocol.\n");
        printf("  --usport          The UDP source port to match on.\n");
        printf("  --udport          The UDP destination port to match on.\n\n");

        printf("  --icmp            Enable or disables matching on the ICMP protocol.\n");
        printf("  --code            The ICMP code to match on.\n");
        printf("  --type            The ICMP type to match on.\n");

        return EXIT_SUCCESS;
    }

    // Check for config file path.
    if ((cli.save || cli.mode == 0) && (!cli.cfg_file || strlen(cli.cfg_file) < 1))
    {
        fprintf(stderr, "[ERROR] CFG file not specified or empty. This is required for filters mode or when saving config.\n");

        return EXIT_FAILURE;
    }

    // Load config.
    config__t cfg = {0};
    
    if (cli.save || cli.mode == 0)
    {
        if ((ret = load_cfg(&cfg, cli.cfg_file, 1, NULL)) != 0)
        {
            fprintf(stderr, "[ERROR] Failed to load config at '%s' (%d)\n", cli.cfg_file, ret);

            return EXIT_FAILURE;
        }

        printf("Loaded config...\n");
    }

    // Handle filters mode.
    if (cli.mode == 0)
    {
        printf("Using filters mode (0)...\n");

        // Retrieve filters map FD.
        int map_filters = get_map_fd_pin(XDP_MAP_PIN_DIR, "map_filters");

        if (map_filters < 0)
        {
            fprintf(stderr, "[ERROR] Failed to retrieve BPF map 'map_filters' from file system.\n");

            return EXIT_FAILURE;
        }

        printf("Using 'map_filters' FD => %d...\n", map_filters);

        // Create new base filter and set its defaults.
        filter_rule_cfg_t new_filter = {0};
        set_filter_defaults(&new_filter);

        new_filter.set = 1;

        // Determine what index we'll be storing this filter at.
        int idx = -1;

        if (cli.idx > 0)
        {
            idx = cli.idx - 1;
        }
        else
        {
            idx = get_next_filter_idx(&cfg);
        }

        if (idx < 0)
        {
            fprintf(stderr, "Failed to retrieve filter next. Make sure you haven't exceeded the maximum filters allowed (%d).\n", MAX_FILTERS);

            return EXIT_FAILURE;
        }

        // Fill out new filter.
        if (cli.enabled > -1)
        {
            new_filter.enabled = cli.enabled;
        }

        if (cli.action > -1)
        {
            new_filter.action = cli.action;
        }

        if (cli.log > -1)
        {
            new_filter.log = cli.log;
        }

        if (cli.block_time > -1)
        {
            new_filter.block_time = cli.block_time;
        }

        if (cli.src_ip)
        {
            new_filter.ip.src_ip = cli.src_ip;
        }

        if (cli.dst_ip)
        {
            new_filter.ip.dst_ip = cli.dst_ip;
        }

        if (cli.src_ip6)
        {
            new_filter.ip.src_ip6 = cli.src_ip6;
        }

        if (cli.dst_ip6)
        {
            new_filter.ip.dst_ip6 = cli.dst_ip6;
        }

        // To Do: See if I can create a macro for below.
        // As long as the naming convention lines up, it should be easily possible.
        if (cli.ip_pps > -1)
        {
            new_filter.ip_pps = cli.ip_pps;
        }

        if (cli.ip_bps > -1)
        {
            new_filter.ip_bps = cli.ip_bps;
        }

        if (cli.flow_pps > -1)
        {
            new_filter.flow_pps = cli.flow_pps;
        }

        if (cli.flow_bps > -1)
        {
            new_filter.flow_bps = cli.flow_bps;
        }

        if (cli.min_ttl > -1)
        {
            new_filter.ip.min_ttl = cli.min_ttl;
        }

        if (cli.max_ttl > -1)
        {
            new_filter.ip.max_ttl = cli.max_ttl;
        }

        if (cli.min_len > -1)
        {
            new_filter.ip.min_len = cli.min_len;
        }

        if (cli.max_len > -1)
        {
            new_filter.ip.max_len = cli.max_len;
        }

        if (cli.tos > -1)
        {
            new_filter.ip.tos = cli.tos;
        }

        if (cli.tcp_enabled > -1)
        {
            new_filter.tcp.enabled = cli.tcp_enabled;
        }

        if (cli.tcp_sport)
        {
            new_filter.tcp.sport = cli.tcp_sport;
        }

        if (cli.tcp_dport)
        {
            new_filter.tcp.dport = cli.tcp_dport;
        }

        if (cli.tcp_urg > -1)
        {
            new_filter.tcp.urg = cli.tcp_urg;
        }

        if (cli.tcp_ack > -1)
        {
            new_filter.tcp.ack = cli.tcp_ack;
        }

        if (cli.tcp_rst > -1)
        {
            new_filter.tcp.rst = cli.tcp_rst;
        }

        if (cli.tcp_psh > -1)
        {
            new_filter.tcp.psh = cli.tcp_psh;
        }

        if (cli.tcp_syn > -1)
        {
            new_filter.tcp.syn = cli.tcp_syn;
        }

        if (cli.tcp_fin > -1)
        {
            new_filter.tcp.fin = cli.tcp_fin;
        }

        if (cli.tcp_ece > -1)
        {
            new_filter.tcp.ece = cli.tcp_ece;
        }

        if (cli.tcp_cwr > -1)
        {
            new_filter.tcp.cwr = cli.tcp_cwr;
        }

        if (cli.udp_enabled > -1)
        {
            new_filter.udp.enabled = cli.udp_enabled;
        }

        if (cli.udp_sport)
        {
            new_filter.udp.sport = cli.udp_sport;
        }

        if (cli.udp_dport)
        {
            new_filter.udp.dport = cli.udp_dport;
        }

        if (cli.icmp_enabled > -1)
        {
            new_filter.icmp.enabled = cli.icmp_enabled;
        }

        if (cli.icmp_code > -1)
        {
            new_filter.icmp.code = cli.icmp_code;
        }

        if (cli.icmp_type > -1)
        {
            new_filter.icmp.type = cli.icmp_type;
        }

        // Set filter at index.
        if (validate_filter(&new_filter) != 0)
        {
            fprintf(stderr, "Invalid filter address, port, or scalar value.\n");
            return EXIT_FAILURE;
        }
        cfg.filters[idx] = new_filter;

        // Update filters.
        fprintf(stdout, "Updating filters (index %d)...\n", idx);

        update_filters(map_filters, &cfg);
    }
    // Handle IPv4 range drop mode.
    else if (cli.mode == 1)
    {
        printf("Using IPv4 range drop mode (1)...\n");

        // Make sure IP range is specified.
        if (!cli.ip)
        {
            fprintf(stderr, "No IP address or range specified. Please set an IP range using -d, --ip arguments.\n");

            return EXIT_FAILURE;
        }

        // Get range map.
        int map_range_drop = get_map_fd_pin(XDP_MAP_PIN_DIR, "map_range_drop");

        if (map_range_drop < 0)
        {
            fprintf(stderr, "Failed to retrieve 'map_range_drop' BPF map FD.\n");

            return EXIT_FAILURE;
        }

        printf("Using 'map_range_drop' FD => %d.\n", map_range_drop);

        // Parse IP range.
        ip_range_t range = parse_ip_range(cli.ip);
        if (!range.success)
        {
            fprintf(stderr, "Invalid IPv4 range: %s\n", cli.ip);
            return EXIT_FAILURE;
        }

        // Attempt to add range.
        if ((ret = add_range_drop(map_range_drop, range.ip, range.cidr)) != 0)
        {
            fprintf(stderr, "Error adding range to BPF map (%d).\n", ret);

            return EXIT_FAILURE;
        }

        printf("Added IP range '%s' to IP range drop map...\n", cli.ip);

        if (cli.save)
        {
            // Get next available index.
            int idx = get_next_ip_drop_range_idx(&cfg);

            if (idx < 0)
            {
                fprintf(stderr, "No available IP drop range indexes. Perhaps the maximum IP ranges has been exceeded?\n");

                return EXIT_FAILURE;
            }

            cfg.drop_ranges[idx] = strdup(cli.ip);
        }
    }
    // Handle block map mode.
    else
    {
        printf("Using source IP block mode (2)...\n");

        if (!cli.ip)
        {
            fprintf(stderr, "No source IP address specified. Please set an IP using -s, --ip arguments.\n");

            return EXIT_FAILURE;
        }

        u64 expires_rel = 0;

        if (cli.expires > 0)
        {
            expires_rel = get_boot_nano_time() + ((u64)cli.expires * 1e9);
        }

        int map_block = get_map_fd_pin(XDP_MAP_PIN_DIR, "map_block");
        int map_block6 = get_map_fd_pin(XDP_MAP_PIN_DIR, "map_block6");

        if (cli.v6)
        {
            if (map_block6 < 0)
            {
                fprintf(stderr, "Failed to find the 'map_block6' BPF map.\n");

                return EXIT_FAILURE;
            }

            printf("Using 'map_block6' FD => %d.\n", map_block6);

            struct in6_addr addr;

            if ((ret = inet_pton(AF_INET6, cli.ip, &addr)) != 1)
            {
                fprintf(stderr, "Failed to convert IPv6 address '%s' to decimal (%d).\n", cli.ip, ret);

                return EXIT_FAILURE;
            }

            u128 ip;
            memcpy(&ip, &addr, sizeof(ip));

            if ((ret = add_block6(map_block6, ip, expires_rel)) != 0)
            {
                fprintf(stderr, "Failed to add IP '%s' to BPF map (%d).\n", cli.ip, ret);

                return EXIT_FAILURE;
            }
        }
        else
        {
            if (map_block < 0)
            {
                fprintf(stderr, "Failed to find the 'map_block' BPF map.\n");

                return EXIT_FAILURE;
            }

            printf("Using 'map_block' FD => %d.\n", map_block);

            struct in_addr addr;

            if ((ret = inet_pton(AF_INET, cli.ip, &addr)) != 1)
            {
                fprintf(stderr, "Failed to convert IP address '%s' to decimal (%d).\n", cli.ip, ret);

                return EXIT_FAILURE;
            }

            if ((ret = add_block(map_block, addr.s_addr, expires_rel)) != 0)
            {
                fprintf(stderr, "Failed to add IP '%s' too BPF map (%d).\n", cli.ip, ret);

                return EXIT_FAILURE;
            }

            if (cli.expires > 0)
            {
                printf("Added '%s' to block map for %lld seconds...\n", cli.ip, cli.expires);
            }
            else
            {
                printf("Added '%s' to block map indefinitely...\n", cli.ip);
            }
        }
    }

    if (cli.save)
    {
        // Save config.
        printf("Saving config...\n");

        if ((ret = save_cfg(&cfg, cli.cfg_file)) != 0)
        {
            fprintf(stderr, "[ERROR] Failed to save config.\n");

            return EXIT_FAILURE;
        }
    }

    printf("Success! Exiting.\n");

    return EXIT_SUCCESS;
}
