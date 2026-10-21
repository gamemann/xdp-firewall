#include <assert.h>
#include <stdarg.h>
#include <unistd.h>
#include <loader/utils/xdp.h>
#include <loader/utils/stats.h>

int cont;
int doing_stats;
static int possible_cpus = 300;
static filter_t rules[MAX_FILTERS];
static int writes;
static int fail_key = -1;
static lpm_trie_key_t range_key;

int libbpf_num_possible_cpus(void)
{
    return possible_cpus;
}

int bpf_map_update_elem(int fd, const void *key, const void *value, __u64 flags)
{
    if (fd == 2)
    {
        range_key = *(const lpm_trie_key_t *)key;
        return 0;
    }
    assert(fd == 1);
    int idx = *(const int *)key;
    assert(idx >= 0 && idx < MAX_FILTERS);
    if (idx == fail_key)
    {
        return -1;
    }
    const filter_t *values = value;
    for (int i = 1; i < possible_cpus; i++)
    {
        assert(memcmp(values, &values[i], sizeof(*values)) == 0);
    }
    rules[idx] = values[0];
    writes++;
    return 0;
}

int bpf_map_lookup_elem(int fd, const void *key, void *value)
{
    assert(fd == 3);
    stats_t *stats = value;
    for (int i = 0; i < possible_cpus; i++)
    {
        stats[i] = (stats_t){.allowed = 1, .dropped = 2, .passed = 3};
    }
    return 0;
}

int bpf_map_delete_elem(int fd, const void *key)
{
    // Array deletion is unsupported. No filter operation should call this.
    assert(fd == 2);
    range_key = *(const lpm_trie_key_t *)key;
    return 0;
}

static void test_parsers(void)
{
    assert(parse_ip_range("255.255.255.255/32").success);
    assert(parse_ip_range("0.0.0.0/0").success);
    assert(parse_ip_range("192.0.2.1").cidr == 32);
    const char *bad_ips[] = {NULL, "", "1.2.3", "1.2.3.4/33", "1.2.3.4/256",
        "1.2.3.4/-1", "1.2.3.4/", "1.2.3.4/24/1", "invalid", "1.2.3.4/24junk",
        "1.2.3.4/+24", "1.2.3.4/ 24"};
    for (size_t i = 0; i < sizeof(bad_ips) / sizeof(*bad_ips); i++)
    {
        assert(!parse_ip_range(bad_ips[i]).success);
    }
    port_range_t range = parse_port_range(" 0 : 65535 ");
    assert(range.success && range.min == 0 && range.max == 65535);
    range = parse_port_range("443");
    assert(range.success && range.min == 443 && range.max == 443);
    const char *bad_ports[] = {NULL, "", "65536", "-1", "80-79", "80-", "80 junk",
        "80-90 junk", "999999999999999999999999999", "80-90-100"};
    for (size_t i = 0; i < sizeof(bad_ports) / sizeof(*bad_ports); i++)
    {
        assert(!parse_port_range(bad_ports[i]).success);
    }
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    u64 before = (u64)now.tv_sec * NANO_TO_SEC + now.tv_nsec;
    assert(get_boot_nano_time() >= before);
}

static void write_config(const char *path, const char *data)
{
    FILE *file = fopen(path, "w");
    assert(file);
    assert(fputs(data, file) >= 0);
    assert(fclose(file) == 0);
}

static void test_config(void)
{
    config__t cfg = {0};
    char path[] = "/tmp/opencode/xdpfw-test-XXXXXX";
    int fd = mkstemp(path);
    assert(fd >= 0);
    close(fd);
    write_config(path, "log_file = \"\"; interface = (\"eth0\", \"eth1\"); filters = ({tcp_enabled=true; tcp_syn=false; tcp_dport=0;});");
    assert(load_cfg(&cfg, path, 1, NULL) == 0);
    assert(cfg.interfaces_cnt == 2 && cfg.filters_cnt == 1);
    assert(cfg.filters[0].tcp.syn == 0);
    assert(save_cfg(&cfg, "/dev/full") != 0);
    assert(cfg.filters[0].ip.min_ttl == -1);
    assert(save_cfg(&cfg, path) == 0);
    assert(load_cfg(&cfg, path, 1, NULL) == 0);
    assert(cfg.log_file == NULL);
    assert(cfg.filters[0].tcp.syn == 0);
    write_config(path, "log_file = \"\"; filters = ({src_ip=\"bad\";});");
    assert(load_cfg(&cfg, path, 1, NULL) != 0);
    assert(cfg.filters_cnt == 1 && cfg.filters[0].tcp.syn == 0);
    assert(cfg.interfaces_cnt == 2);
    write_config(path, "log_file=\"\"; filters=({action=-1;block_time=-1;src_ip6=\"::\";});");
    assert(load_cfg(&cfg, path, 1, NULL) == 0);
    assert(update_filter(1, &cfg.filters[0], 0) == 0);
    assert(rules[0].action == 1 && rules[0].block_time == 1);
    assert(rules[0].ip.do_src_ip6);
    write_config(path, "log_file=\"\"; interface=(\"eth0\",\"eth1\"); filters=({tcp_enabled=true;tcp_syn=false;});");
    assert(load_cfg(&cfg, path, 1, NULL) == 0);
    write_config(path, "broken = ;");
    assert(load_cfg(&cfg, path, 1, NULL) != 0);
    assert(cfg.interfaces_cnt == 2);

    FILE *file = fopen(path, "w");
    assert(file);
    fputs("log_file=\"\"; filters=(", file);
    for (int i = 0; i <= MAX_FILTERS; i++)
    {
        fputs(i ? ",{}" : "{}", file);
    }
    fputs(");", file);
    fclose(file);
    assert(load_cfg(&cfg, path, 1, NULL) != 0);
    assert(cfg.interfaces_cnt == 2);
    write_config(path, "log_file=\"\"; stdout_update_time=0;");
    assert(load_cfg(&cfg, path, 1, NULL) != 0);
    write_config(path, "log_file=\"\"; interface=\"eth2\"; filters=();");
    assert(load_cfg(&cfg, path, 1, NULL) == 0);
    assert(cfg.interfaces_cnt == 1 && cfg.filters_cnt == 0);
    assert(!cfg.interfaces[1]);
    free_cfg(&cfg);
    unlink(path);
}

static void test_maps(void)
{
    writes = 0;
    config__t cfg = {0};
    set_cfg_defaults(&cfg);
    cfg.filters[0].set = 1;
    cfg.filters[0].enabled = 0;
    cfg.filters[1].set = 1;
    cfg.filters[1].ip.src_ip6 = strdup("::1");
    cfg.filters[1].ip.dst_ip6 = strdup("2001:db8:1234:5678::abcd");
    cfg.filters[5].set = 1;
    cfg.filters[5].ip.src_ip = strdup("0.0.0.0/0");
    cfg.filters[5].tcp.enabled = 1;
    cfg.filters[5].tcp.dport = strdup("0");
    // Deliberately leave filters_cnt at zero: sparse CLI additions still work.
    assert(update_filters(1, &cfg) == 0);
    assert(writes == 3); // Two active rules and one sentinel; no deletes.
    struct in6_addr addr;
    inet_pton(AF_INET6, "2001:db8:1234:5678::abcd", &addr);
    assert(memcmp(rules[0].ip.dst_ip6, &addr, 16) == 0);
    inet_pton(AF_INET6, "::1", &addr);
    assert(memcmp(rules[0].ip.src_ip6, &addr, 16) == 0);
    assert(rules[0].ip.do_src_ip6 && rules[0].ip.do_dst_ip6);
    assert(rules[1].ip.do_src_ip && rules[1].ip.src_cidr == 0);
    assert(rules[1].tcp.do_dport_min && rules[1].tcp.dport_min == 0);
    assert(!rules[2].set);
    cfg.filters[1].set = 0;
    cfg.filters[5].set = 0;
    assert(update_filters(1, &cfg) == 0 && !rules[0].set);
    cfg.filters[1].set = 1;
    fail_key = 0;
    assert(update_filters(1, &cfg) != 0);
    fail_key = -1;
    assert(delete_filter(1, 0) == 0 && !rules[0].set);
    assert(update_filter(1, &cfg.filters[1], MAX_FILTERS) != 0);
    assert(add_range_drop(2, inet_addr("192.0.2.12"), 24) == 0);
    assert(range_key.prefix_len == 24 && range_key.data == inet_addr("192.0.2.0"));
    assert(add_range_drop(2, 0, 0) == 0 && range_key.data == 0);
    assert(delete_range_drop(2, 0, 0) == 0 && range_key.prefix_len == 0);
    assert(add_range_drop(2, 0, 33) != 0);
    assert(calc_stats(3, possible_cpus, 0) == 0);
    filter_rule_cfg_t invalid = {0};
    set_filter_defaults(&invalid);
    invalid.set = 1;
    invalid.tcp.dport = strdup("65536");
    assert(update_filter(1, &invalid, 0) != 0);
    set_filter_defaults(&invalid);
    invalid.ip.min_ttl = 256;
    assert(validate_filter(&invalid) != 0);
    set_filter_defaults(&invalid);
    possible_cpus = -1;
    assert(update_filters(1, &cfg) != 0);
    assert(delete_filter(1, 0) != 0);
    assert(calc_stats(3, possible_cpus, 0) != 0);
    possible_cpus = 300;
    free_cfg(&cfg);
}

int main(void)
{
    test_parsers();
    test_config();
    test_maps();
    puts("\nUserspace regression tests passed.");
    return 0;
}
