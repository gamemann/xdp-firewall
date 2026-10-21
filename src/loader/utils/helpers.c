#include <loader/utils/helpers.h>

/**
 * Prints help menu.
 * 
 * @return void
 */
void print_help_menu()
{
    printf("Usage: xdpfw [OPTIONS]\n\n");

    printf("  -c, --config         Config file location (default: /etc/xdpfw/xdpfw.conf).\n");
    printf("  -o, --offload        Load the XDP program in hardware/offload mode.\n");
    printf("  -s, --skb            Force the XDP program to load with SKB mode instead of DRV.\n");
    printf("  -t, --time           Duration to run the program (seconds). 0 or unset = infinite.\n");
    printf("  -l, --list           Print config details including filters (exits after execution).\n");
    printf("  -h, --help           Show this help message.\n\n");
    printf("  -v, --verbose        Override config's verbose value.\n");
    printf("      --log-file       Override config's log file value.\n");
    printf("  -i, --interface      Override config's interface value.\n");
    printf("  -u, --update-time    Override config's update time value.\n");
    printf("  -n, --no-stats       Override config's no stats value.\n");
    printf("      --stats-ps       Override config's stats per second value.\n");
    printf("      --stdout-ut      Override config's stdout update time value.\n");
}

/**
 * Handles signals from user.
 * 
 * @param code Signal code.
 * 
 * @return void
 */
void hdl_signal(int code)
{
    cont = 0;
}

/**
 * Parses an IP string with CIDR support. Stores IP in network byte order in ip.ip and CIDR in ip.cidr.
 * 
 * @param ip The IP string.
 * 
 * @return Returns an IP structure with IP and CIDR. 
 */
ip_range_t parse_ip_range(const char *ip)
{
    ip_range_t ret = {0};
    ret.cidr = 32;

    char ip_copy[INET_ADDRSTRLEN + 3];
    if (!ip || strlen(ip) >= sizeof(ip_copy))
    {
        return ret;
    }
    strcpy(ip_copy, ip);

    char *prefix = strchr(ip_copy, '/');
    if (prefix)
    {
        *prefix++ = '\0';
        if (!isdigit((unsigned char)*prefix))
        {
            return ret;
        }
        char *end;
        errno = 0;
        unsigned long cidr = strtoul(prefix, &end, 10);

        if (errno || end == prefix || *end != '\0' || cidr > 32)
        {
            return ret;
        }
        ret.cidr = cidr;
    }

    struct in_addr addr;
    if (inet_pton(AF_INET, ip_copy, &addr) != 1)
    {
        return ret;
    }

    ret.ip = addr.s_addr;
    ret.success = 1;
    return ret;
}

/**
 * Retrieves protocol name by ID.
 * 
 * @param id The protocol ID
 * 
 * @return The protocol string. 
 */
const char* get_protocol_str_by_id(int id)
{
    switch (id)
    {
        case IPPROTO_TCP:
            return "TCP";

        case IPPROTO_UDP:
            return "UDP";
        
        case IPPROTO_ICMP:
            return "ICMP";
    }

    return "N/A";
}

/**
 * Prints tool name and author.
 * 
 * @return void
 */
void print_tool_info()
{
    printf(
        " __  ______  ____    _____ _                        _ _ \n"
        " \\ \\/ /  _ \\|  _ \\  |  ___(_)_ __ _____      ____ _| | |\n"
        "  \\  /| | | | |_) | | |_  | | '__/ _ \\ \\ /\\ / / _` | | |\n"
        "  /  \\| |_| |  __/  |  _| | | | |  __/\\ V  V / (_| | | |\n"
        " /_/\\_\\____/|_|     |_|   |_|_|  \\___| \\_/\\_/ \\__,_|_|_|\n"
        "\n\n"
    );
}

/**
 * Retrieves nanoseconds since system boot.
 * 
 * @return The current nanoseconds since the system last booted.
 */
u64 get_boot_nano_time()
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
    {
        return 0;
    }

    return (u64)now.tv_sec * NANO_TO_SEC + now.tv_nsec;
}

/**
 * Parses a port range string and returns the minimum and maximum port.
 * 
 * @param range_str The port range string.
 * 
 * @return The port range as port_range_t type. Fields will be set to 0 on failure.
 */
port_range_t parse_port_range(const char* range_str)
{
    port_range_t ret = {0};

    if (!range_str)
    {
        return ret;
    }

    // Copy range string.
    char range_str_copy[24];
    if (strlen(range_str) >= sizeof(range_str_copy))
    {
        return ret;
    }
    strcpy(range_str_copy, range_str);

    // First scan for port ranges with ":".
    char* start = range_str_copy;
    char* end = strchr(range_str_copy, '-');

    if (!end)
    {
        end = strchr(range_str_copy, ':');
    }

    if (end)
    {
        *end = '\0';
        end++;
    }

    char *end_ptr = NULL;

    errno = 0;
    long min = strtol(start, &end_ptr, 10);
    char *digits_end = end_ptr;
    while (isspace((unsigned char)*end_ptr))
    {
        end_ptr++;
    }

    if (errno || digits_end == start || *end_ptr != '\0' || min < 0 || min > 65535)
    {
        return ret;
    }

    long max = min;
    if (end)
    {
        errno = 0;
        max = strtol(end, &end_ptr, 10);
        digits_end = end_ptr;
        while (isspace((unsigned char)*end_ptr))
        {
            end_ptr++;
        }

        if (errno || digits_end == end || *end_ptr != '\0' || max < min || max > 65535)
        {
            return ret;
        }
    }

    ret.min = min;
    ret.max = max;
    ret.success = 1;

    return ret;
}