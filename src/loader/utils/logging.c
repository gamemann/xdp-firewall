#include <loader/utils/logging.h>

/**
 * Prints a log message to stdout/stderr along with a file if specified.
 * 
 * @param req_lvl The required level for this message.
 * @param cur_lvl The current verbose level.
 * @param error If 1, sets pipe to stderr instead of stdout.
 * @param msg The log message.
 * @param args A VA list of arguments for the message.
 * 
 * @return void
 */
static void log_msg_raw(int req_lvl, int cur_lvl, int error, const char* log_path, const char* msg, va_list args)
{
    if (cur_lvl < req_lvl)
    {
        return;
    }

    FILE* pipe = stdout;

    if (error)
    {
        pipe = stderr;
    }

    // We need to format the message.
    va_list args_copy;
    va_copy(args_copy, args);
    int len = vsnprintf(NULL, 0, msg, args_copy);
    va_end(args_copy);

    if (len < 0)
    {
        return;
    }

    char f_msg[len + 1];
    vsnprintf(f_msg, sizeof(f_msg), msg, args);

    char full_msg[len + 6 + 1];
    snprintf(full_msg, sizeof(full_msg), "[%d] %s", req_lvl, f_msg);

    // If we're calculating stats, we need to prepend a new line.
    if (doing_stats)
    {
        printf("\033[F");
        
        fprintf(pipe, "\n%s\n", full_msg);

    }
    else
    {
        fprintf(pipe, "%s\n", full_msg);
    }

    if (log_path != NULL)
    {
        FILE* log_file = fopen(log_path, "a");

        if (!log_file)
        {
            return;
        }

        time_t now = time(NULL);
        struct tm* tm_val = localtime(&now);

        if (!tm_val)
        {
            fclose(log_file);

            return;
        }

        char log_file_msg[len + 22 + 1];

        snprintf(log_file_msg, sizeof(log_file_msg), "[%02d-%02d-%02d %02d:%02d:%02d]%s", tm_val->tm_year % 100, tm_val->tm_mon + 1, tm_val->tm_mday,
        tm_val->tm_hour, tm_val->tm_min, tm_val->tm_sec, full_msg);

        fprintf(log_file, "%s\n", log_file_msg);

        fclose(log_file);
    }
}

/**
 * Prints a log message using log_msg_raw().
 * 
 * @param cfg A pointer to the config structure.
 * @param req_lvl The required level for this message.
 * @param error Whether this is an error.
 * @param msg The log message with format support.
 * 
 * @return void
 */
void log_msg(config__t* cfg, int req_lvl, int error, const char* msg, ...)
{
    va_list args;
    va_start(args, msg);

    log_msg_raw(req_lvl, cfg->verbose, error, (const char*)cfg->log_file, msg, args);

    va_end(args);
}

/**
 * Polls the filters map ringbuffer.
 * 
 * @param rb A pointer to the ringbuffer.
 * 
 * @return void
 */
void poll_filters_rb(struct ring_buffer* rb)
{
    if (rb)
    {
        ring_buffer__poll(rb, RB_TIMEOUT);
    }
}

/**
 * Callback for BPF ringbuffer event (filter logging).
 * 
 * @param ctx The context (should be config__t*).
 * @param data The event data (should be filter_log_event_t*).
 * @param sz The event data size.
 * 
 * @return 0 on success or 1 on failure.
 */
int hdl_filters_rb_event(void* ctx, void* data, size_t sz)
{
    config__t* cfg = (config__t*)ctx;
    filter_log_event_t* e = (filter_log_event_t*)data;

    if (sz < sizeof(*e) || e->filter_id < 0 || e->filter_id >= MAX_FILTERS)
    {
        return 1;
    }
    // Event IDs are compacted BPF keys, not config array indexes.
    filter_rule_cfg_t* filter = NULL;
    int key = 0;
    int cfg_idx = 0;
    for (; cfg_idx < MAX_FILTERS; cfg_idx++)
    {
        if (!cfg->filters[cfg_idx].set || !cfg->filters[cfg_idx].enabled)
        {
            continue;
        }
        if (key++ == e->filter_id)
        {
            filter = &cfg->filters[cfg_idx];
            break;
        }
    }
    if (!filter)
    {
        return 1;
    }

    char src_ip_str[INET6_ADDRSTRLEN];
    char dst_ip_str[INET6_ADDRSTRLEN];

    if (memcmp(e->src_ip6, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 16) != 0)
    {
        inet_ntop(AF_INET6, e->src_ip6, src_ip_str, sizeof(src_ip_str));
        inet_ntop(AF_INET6, e->dst_ip6, dst_ip_str, sizeof(dst_ip_str));
    }
    else
    {
        inet_ntop(AF_INET, &e->src_ip, src_ip_str, sizeof(src_ip_str));
        inet_ntop(AF_INET, &e->dst_ip, dst_ip_str, sizeof(dst_ip_str));
    }

    char* action = "Dropped";
    
    if (filter->action == 1)
    {
        action = "Passed";
    }

    const char* protocol_str = get_protocol_str_by_id(e->protocol);

    log_msg(cfg, 0, 0, "[FILTER %d] %s %s packet '%s:%d' => '%s:%d' (IP PPS => %llu, IP BPS => %llu, Flow PPS => %llu, Flow BPS => %llu Filter Block Time => %d, length => %d)...", cfg_idx + 1, action, protocol_str, src_ip_str, ntohs(e->src_port), dst_ip_str, ntohs(e->dst_port), e->ip_pps, e->ip_bps, e->flow_pps, e->flow_bps, filter->block_time, e->length);

    return 0;
}
