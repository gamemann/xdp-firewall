#include <xdp/utils/rule.h>

#ifdef ENABLE_FILTERS
/**
 * Processes a filter rule.
 * 
 * @param idx The rule index.
 * @param data A pointer to the rule context.
 * 
 * @return 1 to break the loop or 0 to continue.
 */
static __always_inline long process_rule(u32 idx, void* data)
{
    rule_ctx_t* ctx = data;

    filter_t *filter = bpf_map_lookup_elem(&map_filters, &idx);

    if (!filter || !filter->set)
    {
        return 1;
    }

#ifdef ENABLE_RL_IP
    // Check source IP rate limits.
    if (filter->do_ip_pps && ctx->ip_pps < filter->ip_pps)
    {
        return 0;
    }

    if (filter->do_ip_bps && ctx->ip_bps < filter->ip_bps)
    {
        return 0;
    }
#endif

#ifdef ENABLE_RL_FLOW
    // Check source flow rate limits.
    if (filter->do_flow_pps && ctx->flow_pps < filter->flow_pps)
    {
        return 0;
    }

    if (filter->do_flow_bps && ctx->flow_bps < filter->flow_bps)
    {
        return 0;
    }
#endif

    // Max packet length.
    if (filter->ip.do_max_len && filter->ip.max_len < ctx->pkt_len)
    {
        return 0;
    }

    // Min packet length.
    if (filter->ip.do_min_len && filter->ip.min_len > ctx->pkt_len)
    {
        return 0;
    }

    // Match IP settings.
    if (ctx->iph)
    {
        // Source address.
        if (filter->ip.do_src_ip)
        {
            if (!is_ip_in_range(ctx->iph->saddr, filter->ip.src_ip, filter->ip.src_cidr))
            {
                return 0;
            }
        }

        // Destination address.
        if (filter->ip.do_dst_ip)
        {
            if (!is_ip_in_range(ctx->iph->daddr, filter->ip.dst_ip, filter->ip.dst_cidr))
            {
                return 0;
            }
        }

#if defined(ENABLE_IPV6) && defined(ALLOW_SINGLE_IP_V4_V6)
        if (filter->ip.do_src_ip6 || filter->ip.do_dst_ip6)
        {
            return 0;
        }
#endif

        // TOS.
        if (filter->ip.do_tos && filter->ip.tos != ctx->iph->tos)
        {
            return 0;
        }

        // Max TTL.
        if (filter->ip.do_max_ttl && filter->ip.max_ttl < ctx->iph->ttl)
        {
            return 0;
        }

        // Min TTL.
        if (filter->ip.do_min_ttl && filter->ip.min_ttl > ctx->iph->ttl)
        {
            return 0;
        }
    }
#ifdef ENABLE_IPV6
    else if (ctx->iph6)
    {
        // Source address.
        if (filter->ip.do_src_ip6 && (ctx->iph6->saddr.in6_u.u6_addr32[0] != filter->ip.src_ip6[0] || ctx->iph6->saddr.in6_u.u6_addr32[1] != filter->ip.src_ip6[1] || ctx->iph6->saddr.in6_u.u6_addr32[2] != filter->ip.src_ip6[2] || ctx->iph6->saddr.in6_u.u6_addr32[3] != filter->ip.src_ip6[3]))
        {
            return 0;
        }

        // Destination address.
        if (filter->ip.do_dst_ip6 && (ctx->iph6->daddr.in6_u.u6_addr32[0] != filter->ip.dst_ip6[0] || ctx->iph6->daddr.in6_u.u6_addr32[1] != filter->ip.dst_ip6[1] || ctx->iph6->daddr.in6_u.u6_addr32[2] != filter->ip.dst_ip6[2] || ctx->iph6->daddr.in6_u.u6_addr32[3] != filter->ip.dst_ip6[3]))
        {
            return 0;
        }

#ifdef ALLOW_SINGLE_IP_V4_V6
        if (filter->ip.do_src_ip || filter->ip.do_dst_ip)
        {
            return 0;
        }
#endif

        // Max TTL length.
        if (filter->ip.do_max_ttl && filter->ip.max_ttl < ctx->iph6->hop_limit)
        {
            return 0;
        }

        // Min TTL length.
        if (filter->ip.do_min_ttl && filter->ip.min_ttl > ctx->iph6->hop_limit)
        {
            return 0;
        }
    }
#endif

    // Check TCP matches.
    if (filter->tcp.enabled)
    {
        if (!ctx->tcph)
        {
            return 0;
        }

        // Source port checks.
        if (filter->tcp.do_sport_min && ntohs(ctx->tcph->source) < filter->tcp.sport_min)
        {
            return 0;
        }

        if (filter->tcp.do_sport_max && ntohs(ctx->tcph->source) > filter->tcp.sport_max)
        {
            return 0;
        }

        // Destination port checks.
        if (filter->tcp.do_dport_min && ntohs(ctx->tcph->dest) < filter->tcp.dport_min)
        {
            return 0;
        }

        if (filter->tcp.do_dport_max && ntohs(ctx->tcph->dest) > filter->tcp.dport_max)
        {
            return 0;
        }

        // URG flag.
        if (filter->tcp.do_urg && filter->tcp.urg != ctx->tcph->urg)
        {
            return 0;
        }

        // ACK flag.
        if (filter->tcp.do_ack && filter->tcp.ack != ctx->tcph->ack)
        {
            return 0;
        }

        // RST flag.
        if (filter->tcp.do_rst && filter->tcp.rst != ctx->tcph->rst)
        {
            return 0;
        }

        // PSH flag.
        if (filter->tcp.do_psh && filter->tcp.psh != ctx->tcph->psh)
        {
            return 0;
        }

        // SYN flag.
        if (filter->tcp.do_syn && filter->tcp.syn != ctx->tcph->syn)
        {
            return 0;
        }

        // FIN flag.
        if (filter->tcp.do_fin && filter->tcp.fin != ctx->tcph->fin)
        {
            return 0;
        }

        // ECE flag.
        if (filter->tcp.do_ece && filter->tcp.ece != ctx->tcph->ece)
        {
            return 0;
        }

        // CWR flag.
        if (filter->tcp.do_cwr && filter->tcp.cwr != ctx->tcph->cwr)
        {
            return 0;
        }
    }
    // Check UDP matches.
    else if (filter->udp.enabled)
    {
        if (!ctx->udph)
        {
            return 0;
        }

        // Source port checks.
        if (filter->udp.do_sport_min && ntohs(ctx->udph->source) < filter->udp.sport_min)
        {
            return 0;
        }

        if (filter->udp.do_sport_max && ntohs(ctx->udph->source) > filter->udp.sport_max)
        {
            return 0;
        }

        // Destination port checks.
        if (filter->udp.do_dport_min && ntohs(ctx->udph->dest) < filter->udp.dport_min)
        {
            return 0;
        }

        if (filter->udp.do_dport_max && ntohs(ctx->udph->dest) > filter->udp.dport_max)
        {
            return 0;
        }
    }
    else if (filter->icmp.enabled)
    {
        if (ctx->icmph)
        {
            // Code.
            if (filter->icmp.do_code && filter->icmp.code != ctx->icmph->code)
            {
                return 0;
            }

            // Type.
            if (filter->icmp.do_type && filter->icmp.type != ctx->icmph->type)
            {
                return 0;
            }  
        }
#ifdef ENABLE_IPV6
        else if (ctx->icmph6)
        {
            // Code.
            if (filter->icmp.do_code && filter->icmp.code != ctx->icmph6->icmp6_code)
            {
                return 0;
            }

            // Type.
            if (filter->icmp.do_type && filter->icmp.type != ctx->icmph6->icmp6_type)
            {
                return 0;
            }
        }
#endif
        else
        {
            return 0;
        }
    }

#ifdef ENABLE_FILTER_LOGGING
    if (filter->log > 0)
    {
        log_filter_msg(ctx->iph, ctx->iph6, ctx->src_port, ctx->dst_port, ctx->protocol, ctx->now, ctx->ip_pps, ctx->ip_bps, ctx->flow_pps, ctx->flow_bps, ctx->pkt_len, idx);
    }
#endif
    
    // Matched.
    ctx->matched = 1;
    ctx->action = filter->action;
    ctx->block_time = filter->block_time;

    return 1;
}
#endif
