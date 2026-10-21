#pragma once

#include <common/all.h>

#include <string.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>

#include <string.h>
#include <ctype.h>

#include <sys/sysinfo.h>
#include <time.h>
#include <errno.h>

struct ip_range
{
    u32 ip;
    u8 cidr;
    unsigned int success;
} typedef ip_range_t;

struct port_range
{
    unsigned int success;
    u16 min;
    u16 max;
} typedef port_range_t;

extern int cont;

void print_help_menu();
void hdl_signal(int code);
ip_range_t parse_ip_range(const char* ip);
const char* get_protocol_str_by_id(int id);
void print_tool_info();
u64 get_boot_nano_time();
port_range_t parse_port_range(const char* range_str);
