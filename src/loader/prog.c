#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>

#include <signal.h>

#include <sys/resource.h>
#include <sys/sysinfo.h>
#include <sys/stat.h>

#include <net/if.h>

#include <loader/utils/cli.h>
#include <loader/utils/config.h>
#include <loader/utils/xdp.h>
#include <loader/utils/logging.h>
#include <loader/utils/stats.h>
#include <loader/utils/helpers.h>

int cont = 1;
int doing_stats = 0;

/**
 * Unpins required BPF maps from file system.
 * 
 * @param cfg A pointer to the config structure.
 * @param obj A pointer to the BPF object.
 * @param ignore_errors Whether to ignore errors.
 */
static void unpin_needed_maps(config__t* cfg, struct bpf_object* obj, int ignore_errors)
{
    int ret;

    // Unpin stats map.
    if ((ret = unpin_bpf_map(obj, XDP_MAP_PIN_DIR, "map_stats")) != 0)
    {
        if (!ignore_errors)
        {
            log_msg(cfg, 1, 0, "[WARNING] Failed to un-pin BPF map 'map_stats' from file system (%d).", ret);
        }
    }

    // Unpin block map.
    if ((ret = unpin_bpf_map(obj, XDP_MAP_PIN_DIR, "map_block")) != 0)
    {
        if (!ignore_errors)
        {
            log_msg(cfg, 1, 0, "[WARNING] Failed to un-pin BPF map 'map_block' from file system (%d).", ret);
        }
    }
#ifdef ENABLE_IPV6
    // Unpin block (IPv6) map.
    if ((ret = unpin_bpf_map(obj, XDP_MAP_PIN_DIR, "map_block6")) != 0)
    {
        if (!ignore_errors)
        {
            log_msg(cfg, 1, 0, "[WARNING] Failed to un-pin BPF map 'map_block6' from file system (%d).", ret);
        }
    }
#endif

#ifdef ENABLE_IP_RANGE_DROP
    // Unpin IPv4 range drop map.
    if ((ret = unpin_bpf_map(obj, XDP_MAP_PIN_DIR, "map_range_drop")) != 0)
    {
        if (!ignore_errors)
        {
            log_msg(cfg, 1, 0, "[WARNING] Failed to un-pin BPF map 'map_range_drop' from file system (%d).", ret);
        }
    }
#endif

#ifdef ENABLE_FILTERS
    // Unpin filters map.
    if ((ret = unpin_bpf_map(obj, XDP_MAP_PIN_DIR, "map_filters")) != 0)
    {
        if (!ignore_errors)
        {
            log_msg(cfg, 1, 0, "[WARNING] Failed to un-pin BPF map 'map_filters' from file system (%d).", ret);
        }
    }

#ifdef ENABLE_FILTER_LOGGING
    // Unpin filters log map.
    if ((ret = unpin_bpf_map(obj, XDP_MAP_PIN_DIR, "map_filter_log")) != 0)
    {
        if (!ignore_errors)
        {
            log_msg(cfg, 1, 0, "[WARNING] Failed to un-pin BPF map 'map_filter_log' from file system (%d).", ret);
        }
    }
#endif
#endif
}

int main(int argc, char *argv[])
{
    int ret;

    // Parse the command line.
    cli_t cli = {0};
    cli.cfg_file = CONFIG_DEFAULT_PATH;
    cli.verbose = -1;
    cli.pin_maps = -1;
    cli.update_time = -1;
    cli.no_stats = -1;
    cli.stats_per_second = -1;
    cli.stdout_update_time = -1;

    parse_cli(&cli, argc, argv);

    // Check for help.
    if (cli.help)
    {
        print_help_menu();

        return EXIT_SUCCESS;
    }

    // Initialize config.
    config__t cfg = {0};

    // Create overrides for config and set arguments from CLI.
    config_overrides_t cfg_overrides = {0};
    cfg_overrides.verbose = cli.verbose;
    cfg_overrides.log_file = cli.log_file;
    cfg_overrides.interface = cli.interface;
    cfg_overrides.pin_maps = cli.pin_maps;
    cfg_overrides.update_time = cli.update_time;
    cfg_overrides.no_stats = cli.no_stats;
    cfg_overrides.stats_per_second = cli.stats_per_second;
    cfg_overrides.stdout_update_time = cli.stdout_update_time;

    // Load config.
    if ((ret = load_cfg(&cfg, cli.cfg_file, 1, &cfg_overrides)) != 0)
    {
        fprintf(stderr, "[ERROR] Failed to load config from file system (%s)(%d).\n", cli.cfg_file, ret);

        return EXIT_FAILURE;
    }

    // Check for list option.
    if (cli.list)
    {
        print_cfg(&cfg);
        free_cfg(&cfg);

        return EXIT_SUCCESS;
    }

    // Print tool info.
    if (cfg.verbose > 0)
    {
        print_tool_info();
    }

    // Check first interface.
    if (!cfg.interfaces[0])
    {
        log_msg(&cfg, 0, 1, "[ERROR] No interface(s) specified in config or CLI override.");

        return EXIT_FAILURE;
    }

    log_msg(&cfg, 2, 0, "Raising RLimit...");

    // Raise RLimit.
    struct rlimit rl = { RLIM_INFINITY, RLIM_INFINITY };

    if (setrlimit(RLIMIT_MEMLOCK, &rl)) 
    {
        log_msg(&cfg, 0, 1, "[ERROR] Failed to raise rlimit. Please make sure this program is ran as root!\n");

        return EXIT_FAILURE;
    }

    log_msg(&cfg, 2, 0, "Loading XDP/BPF program at '%s'...", XDP_OBJ_PATH);

    // Determine custom LibBPF log level.
    int silent = 1;

    if (cfg.verbose > 4)
    {
        silent = 0;
    }

    set_libbpf_log_mode(silent);

    // Load BPF object.
    struct xdp_program *prog = load_bpf_obj(XDP_OBJ_PATH);

    if (prog == NULL)
    {
        log_msg(&cfg, 0, 1, "[ERROR] Failed to load eBPF object file. Object path => %s.\n", XDP_OBJ_PATH);

        return EXIT_FAILURE;
    }

    int if_idx[MAX_INTERFACES] = {0};
    int attach_success = 0;

    // Attach XDP program to interface(s).
    for (int i = 0; i < cfg.interfaces_cnt; i++)
    {
        const char* interface = cfg.interfaces[i];

        if (!interface)
        {
            continue;
        }

        log_msg(&cfg, 4, 0, "Retrieving interface index for '%s'...", interface);

        // Get interface index.
        if_idx[i] = if_nametoindex(interface);
    
        if (if_idx[i] == 0)
        {
            log_msg(&cfg, 0, 1, "[WARNING] Failed to retrieve index of network interface '%s'.\n", interface);
    
            continue;
        }

        log_msg(&cfg, 3, 0, "Interface index for '%s' => %d.", interface, if_idx[i]);

        log_msg(&cfg, 2, 0, "Attaching XDP program to interface '%s'...", interface);
    
        // Attach XDP program.
        char* mode_used = NULL;
    
        if ((ret = attach_xdp(prog, &mode_used, if_idx[i], 0, cli.skb, cli.offload)) != 0)
        {
            log_msg(&cfg, 0, 1, "[WARNING] Failed to attach XDP program to interface '%s' using available modes (%d).\n", interface, ret);
            if_idx[i] = 0;

            continue;
        }
    
        if (mode_used != NULL)
        {
            log_msg(&cfg, 1, 0, "Attached XDP program to interface '%s' using mode '%s'...", interface, mode_used);
        }

        if (!attach_success)
        {
            attach_success = 1;
        }
    }

    if (!attach_success)
    {
        log_msg(&cfg, 0, 1, "[ERROR] Failed to attach XDP program to any configured interfaces.");

        return EXIT_FAILURE;
    }

    log_msg(&cfg, 2, 0, "Retrieving BPF map FDs...");

    // Retrieve BPF maps.
    int map_stats = get_map_fd(prog, "map_stats");

    if (map_stats < 0)
    {
        log_msg(&cfg, 0, 1, "[ERROR] Failed to find 'map_stats' BPF map.\n");

        return EXIT_FAILURE;
    }

#ifdef ENABLE_FILTERS
    int map_filters = get_map_fd(prog, "map_filters");

    // Check for valid maps.
    if (map_filters < 0)
    {
        log_msg(&cfg, 0, 1, "[ERROR] Failed to find 'map_filters' BPF map.\n");

        return EXIT_FAILURE;
    }

    log_msg(&cfg, 3, 0, "map_filters FD => %d.", map_filters);

#ifdef ENABLE_FILTER_LOGGING
    int map_filter_log = get_map_fd(prog, "map_filter_log");

    struct ring_buffer* rb = NULL;

    if (map_filter_log < 0)
    {
        log_msg(&cfg, 1, 0, "[WARNING] Failed to find 'map_filter_log' BPF map. Filter logging will be disabled...");
    }
    else
    {
        log_msg(&cfg, 3, 0, "map_filter_log FD => %d.", map_filter_log);

        rb = ring_buffer__new(map_filter_log, hdl_filters_rb_event, &cfg, NULL);
    }
#endif
#endif

#ifdef ENABLE_IP_RANGE_DROP
    int map_range_drop = get_map_fd(prog, "map_range_drop");

    if (map_range_drop < 0)
    {
        log_msg(&cfg, 1, 0, "[WARNING] Failed to find 'map_range_drop' BPF map. IP range drops will be disabled...");
    }
    else
    {
        log_msg(&cfg, 3, 0, "map_range_drop FD => %d.", map_range_drop);
    }
#endif

    log_msg(&cfg, 3, 0, "map_stats FD => %d.", map_stats);

    // Pin BPF maps to file system if we need to.
    const int pin_maps = cfg.pin_maps;
    if (pin_maps)
    {
        log_msg(&cfg, 2, 0, "Pinning BPF maps...");

        struct bpf_object* obj = get_bpf_obj(prog);

        // There are times where the BPF maps from the last run weren't cleaned up properly.
        // So it's best to attempt to unpin the maps before pinning while ignoring errors.
        unpin_needed_maps(&cfg, obj, 1);

        // Pin the stats map.
        if ((ret = pin_bpf_map(obj, XDP_MAP_PIN_DIR, "map_stats")) != 0)
        {
            log_msg(&cfg, 1, 0, "[WARNING] Failed to pin 'map_stats' to file system (%d)...", ret);
        }
        else
        {
            log_msg(&cfg, 3, 0, "BPF map 'map_stats' pinned to '%s/map_stats'.", XDP_MAP_PIN_DIR);
        }

        // Pin the block maps.
        if ((ret = pin_bpf_map(obj, XDP_MAP_PIN_DIR, "map_block")) != 0)
        {
            log_msg(&cfg, 1, 0, "[WARNING] Failed to pin 'map_block' to file system (%d)...", ret);
        }
        else
        {
            log_msg(&cfg, 3, 0, "BPF map 'map_block' pinned to '%s/map_block'.", XDP_MAP_PIN_DIR);
        }
#ifdef ENABLE_IPV6
        if ((ret = pin_bpf_map(obj, XDP_MAP_PIN_DIR, "map_block6")) != 0)
        {
            log_msg(&cfg, 1, 0, "[WARNING] Failed to pin 'map_block6' to file system (%d)...", ret);
        }
        else
        {
            log_msg(&cfg, 3, 0, "BPF map 'map_block6' pinned to '%s/map_block6'.", XDP_MAP_PIN_DIR);
        }
#endif

#ifdef ENABLE_IP_RANGE_DROP
        // Pin the IPv4 range drop map.
        if ((ret = pin_bpf_map(obj, XDP_MAP_PIN_DIR, "map_range_drop")) != 0)
        {
            log_msg(&cfg, 1, 0, "[WARNING] Failed to pin 'map_range_drop' to file system (%d)...", ret);
        }
        else
        {
            log_msg(&cfg, 3, 0, "BPF map 'map_range_drop' pinned to '%s/map_range_drop'.", XDP_MAP_PIN_DIR);
        }
#endif

#ifdef ENABLE_FILTERS
        // Pin the filters map.
        if ((ret = pin_bpf_map(obj, XDP_MAP_PIN_DIR, "map_filters")) != 0)
        {
            log_msg(&cfg, 1, 0, "[WARNING] Failed to pin 'map_filters' to file system (%d)...", ret);
        }
        else
        {
            log_msg(&cfg, 3, 0, "BPF map 'map_filters' pinned to '%s/map_filters'.", XDP_MAP_PIN_DIR);
        }

#ifdef ENABLE_FILTER_LOGGING
        // Pin the filters log map.
        if ((ret = pin_bpf_map(obj, XDP_MAP_PIN_DIR, "map_filter_log")) != 0)
        {
            log_msg(&cfg, 1, 0, "[WARNING] Failed to pin 'map_filter_log' to file system (%d)...", ret);
        }
        else
        {
            log_msg(&cfg, 3, 0, "BPF map 'map_filter_log' pinned to '%s/map_filter_log'.", XDP_MAP_PIN_DIR);
        }
#endif
#endif
    }

#ifdef ENABLE_FILTERS
    log_msg(&cfg, 2, 0, "Updating filters...");

    // Update filters.
    if (update_filters(map_filters, &cfg) != 0)
    {
        log_msg(&cfg, 0, 1, "[ERROR] Failed to populate filter map.");
    }
#endif

#ifdef ENABLE_IP_RANGE_DROP
    if (map_range_drop > -1)
    {
        log_msg(&cfg, 2, 0, "Updating IP drop ranges...");

        // Update IP range drops.
        update_range_drops(map_range_drop, &cfg);
    }
#endif

    // Signal.
    signal(SIGINT, hdl_signal);
    signal(SIGTERM, hdl_signal);

    // Receive CPU count for stats map parsing.
    int cpus = libbpf_num_possible_cpus();

    log_msg(&cfg, 4, 0, "Retrieved %d CPUs on host.", cpus);

    unsigned int end_time = (cli.time > 0) ? time(NULL) + cli.time : 0;

    // Create last updated variables.
    time_t last_update_check = time(NULL);
    time_t last_config_check = time(NULL);

    struct stat conf_stat;

    // Check if we're doing stats.
    if (!cfg.no_stats)
    {
        doing_stats = 1;
    }

    while (cont)
    {
        // Get current time.
        time_t cur_time = time(NULL);

        // Check if we should end the program.
        if (end_time > 0 && cur_time >= end_time)
        {
            break;
        }

        // Check for auto-update.
        if (cfg.update_time > 0 && (cur_time - last_update_check) > cfg.update_time)
        {
            log_msg(&cfg, 6, 0, "Checking for config updates...");

            // Check if config file have been modified
            if (stat(cli.cfg_file, &conf_stat) == 0 && conf_stat.st_mtime > last_config_check) {
                log_msg(&cfg, 3, 0, "Config file change detected during update. Attempting to reload config...");
                
                // Reload config.
                if ((ret = load_cfg(&cfg, cli.cfg_file, 1, &cfg_overrides)) != 0)
                {
                    log_msg(&cfg, 1, 0, "[WARNING] Failed to load config after update check (%d)...\n", ret);
                }
                else
                {
                    log_msg(&cfg, 4, 0, "Config reloaded successfully...");

                    // Make sure we set doing_stats properly.
                    if (!cfg.no_stats && !doing_stats)
                    {
                        doing_stats = 1;
                    }
                    else if (cfg.no_stats && doing_stats)
                    {
                        doing_stats = 0;
                    }

#ifdef ENABLE_FILTERS
                    // Update filters.
                    if (update_filters(map_filters, &cfg) != 0)
                    {
                        log_msg(&cfg, 0, 1, "[ERROR] Failed to update filter map.");
                    }
#endif
                    last_config_check = conf_stat.st_mtime;
                }

            }

            // Update last updated variable.
            last_update_check = time(NULL);
        }

        // Calculate and display stats if enabled.
        if (!cfg.no_stats)
        {
            if (calc_stats(map_stats, cpus, cfg.stats_per_second))
            {
                log_msg(&cfg, 1, 0, "[WARNING] Failed to calculate packet stats. Stats map FD => %d...\n", map_stats);
            }
        }

#if defined(ENABLE_FILTERS) && defined(ENABLE_FILTER_LOGGING)
        poll_filters_rb(rb);
#endif

        usleep((unsigned int)cfg.stdout_update_time * 1000);
    }

    fprintf(stdout, "\n");

    log_msg(&cfg, 2, 0, "Cleaning up...");

#if defined(ENABLE_FILTERS) && defined(ENABLE_FILTER_LOGGING)
    if (rb)
    {
        ring_buffer__free(rb);
    }
#endif

    // Detach XDP program from interfaces.
    for (int i = 0; i < MAX_INTERFACES; i++)
    {
        if (if_idx[i] == 0)
        {
            continue;
        }

        char* mode_used = NULL;

        if (attach_xdp(prog, &mode_used, if_idx[i], 1, cli.skb, cli.offload))
        {
            log_msg(&cfg, 0, 0, "[WARNING] Failed to detach XDP program from interface index %d.\n", if_idx[i]);
        }
    }

    // Unpin maps from file system.
    if (pin_maps)
    {
        log_msg(&cfg, 2, 0, "Un-pinning BPF maps from file system...");

        struct bpf_object* obj = get_bpf_obj(prog);

        unpin_needed_maps(&cfg, obj, 0);
    }

    // Lastly, close the XDP program.
    xdp_program__close(prog);

    log_msg(&cfg, 1, 0, "Exiting.\n");
    free_cfg(&cfg);

    // Exit program successfully.
    return EXIT_SUCCESS;
}
