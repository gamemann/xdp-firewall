CC = clang

LIBXDP_STATIC ?= 1

# Top-level directories.
BUILD_DIR = build
SRC_DIR = src
MODULES_DIR = modules

# Common directories.
COMMON_DIR = $(SRC_DIR)/common
ETC_DIR = /etc/xdpfw

# Project source directories.
LOADER_DIR = $(SRC_DIR)/loader
XDP_DIR = $(SRC_DIR)/xdp

RULE_ADD_DIR = $(SRC_DIR)/rule_add
RULE_DEL_DIR = $(SRC_DIR)/rule_del

# Additional build directories.
BUILD_LOADER_DIR = $(BUILD_DIR)/loader
BUILD_XDP_DIR = $(BUILD_DIR)/xdp
BUILD_RULE_ADD_DIR = $(BUILD_DIR)/rule_add
BUILD_RULE_DEL_DIR = $(BUILD_DIR)/rule_del

# XDP Tools directories.
XDP_TOOLS_DIR = $(MODULES_DIR)/xdp-tools
XDP_TOOLS_HEADERS = $(XDP_TOOLS_DIR)/headers

# LibXDP and LibBPF directories.
LIBXDP_DIR = $(XDP_TOOLS_DIR)/lib/libxdp
LIBBPF_DIR = $(XDP_TOOLS_DIR)/lib/libbpf

LIBBPF_SRC = $(LIBBPF_DIR)/src

# LibBPF objects.
LIBBPF_OBJS = $(addprefix $(LIBBPF_SRC)/staticobjs/, $(notdir $(wildcard $(LIBBPF_SRC)/staticobjs/*.o)))

# LibXDP objects.
# To Do: Figure out why static objects produces errors relating to unreferenced functions with dispatcher.
# Note: Not sure why shared objects are acting like static objects here where we can link while building and then don't require them at runtime, etc.
LIBXDP_OBJS = $(addprefix $(LIBXDP_DIR)/sharedobjs/, $(notdir $(wildcard $(LIBXDP_DIR)/sharedobjs/*.o)))

# Loader directories.
LOADER_SRC = prog.c
LOADER_OUT = xdpfw

LOADER_UTILS_DIR = $(LOADER_DIR)/utils

# Loader utils.
LOADER_UTILS_CONFIG_SRC = config.c
LOADER_UTILS_CONFIG_OBJ = config.o

LOADER_UTILS_cli_SRC = cli.c
LOADER_UTILS_cli_OBJ = cli.o

LOADER_UTILS_XDP_SRC = xdp.c
LOADER_UTILS_XDP_OBJ = xdp.o

LOADER_UTILS_LOGGING_SRC = logging.c
LOADER_UTILS_LOGGING_OBJ = logging.o

LOADER_UTILS_STATS_SRC = stats.c
LOADER_UTILS_STATS_OBJ = stats.o

LOADER_UTILS_HELPERS_SRC = helpers.c
LOADER_UTILS_HELPERS_OBJ = helpers.o

# Loader objects.
LOADER_OBJS = $(BUILD_LOADER_DIR)/$(LOADER_UTILS_CONFIG_OBJ) $(BUILD_LOADER_DIR)/$(LOADER_UTILS_cli_OBJ) $(BUILD_LOADER_DIR)/$(LOADER_UTILS_XDP_OBJ) $(BUILD_LOADER_DIR)/$(LOADER_UTILS_LOGGING_OBJ) $(BUILD_LOADER_DIR)/$(LOADER_UTILS_STATS_OBJ) $(BUILD_LOADER_DIR)/$(LOADER_UTILS_HELPERS_OBJ)

ifeq ($(LIBXDP_STATIC), 1)
	LOADER_OBJS := $(LIBBPF_OBJS) $(LIBXDP_OBJS) $(LOADER_OBJS)
endif

# XDP directories.
XDP_SRC = prog.c
XDP_OBJ = xdp_prog.o

# Rule common.
RULE_OBJS = $(BUILD_LOADER_DIR)/$(LOADER_UTILS_CONFIG_OBJ) $(BUILD_LOADER_DIR)/$(LOADER_UTILS_XDP_OBJ) $(BUILD_LOADER_DIR)/$(LOADER_UTILS_LOGGING_OBJ) $(BUILD_LOADER_DIR)/$(LOADER_UTILS_HELPERS_OBJ)

ifeq ($(LIBXDP_STATIC), 1)
	RULE_OBJS := $(LIBBPF_OBJS) $(LIBXDP_OBJS) $(RULE_OBJS)
endif

# Rule add.
RULE_ADD_SRC = prog.c
RULE_ADD_OUT = xdpfw-add

RULE_ADD_UTILS_DIR = $(RULE_ADD_DIR)/utils

# Rule add utils.
RULE_ADD_UTILS_cli_SRC = cli.c
RULE_ADD_UTILS_cli_OBJ = cli.o

RULE_ADD_OBJS = $(BUILD_RULE_ADD_DIR)/$(RULE_ADD_UTILS_cli_OBJ)

# Rule delete.
RULE_DEL_SRC = prog.c
RULE_DEL_OUT = xdpfw-del

RULE_DEL_UTILS_DIR = $(RULE_DEL_DIR)/utils

# Rule delete utils.
RULE_DEL_UTILS_cli_SRC = cli.c
RULE_DEL_UTILS_cli_OBJ = cli.o

RULE_DEL_OBJS = $(BUILD_RULE_DEL_DIR)/$(RULE_DEL_UTILS_cli_OBJ)

# Includes.
INCS = -I $(SRC_DIR) -I /usr/include -I /usr/local/include

ifeq ($(LIBXDP_STATIC), 1)
	INCS += -I $(XDP_TOOLS_HEADERS) -I $(LIBBPF_SRC)
endif

# Flags.
FLAGS = -O2 -g
FLAGS_LOADER = -lconfig -lelf -lz

ifeq ($(LIBXDP_STATIC), 1)
	FLAGS += -D__LIBXDP_STATIC__
else
	FLAGS_LOADER += -lbpf -lxdp
endif

# All chains.
all: loader xdp rule_add rule_del

# Rootless regression tests with mocked BPF maps/helpers.
TEST_FLAGS ?= -O1 -g -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer
TEST_INCS = -I $(SRC_DIR) -I $(XDP_TOOLS_HEADERS) -I $(LIBBPF_SRC)

test:
	mkdir -p $(BUILD_DIR)/tests
	$(CC) $(TEST_INCS) $(TEST_FLAGS) -D__LIBXDP_STATIC__ -ffunction-sections -fdata-sections -Wl,--gc-sections -o $(BUILD_DIR)/tests/userspace tests/userspace.c $(LOADER_UTILS_DIR)/config.c $(LOADER_UTILS_DIR)/helpers.c $(LOADER_UTILS_DIR)/xdp.c $(LOADER_UTILS_DIR)/stats.c $(LOADER_UTILS_DIR)/logging.c -lconfig
	$(BUILD_DIR)/tests/userspace
	$(CC) $(TEST_INCS) $(TEST_FLAGS) -D__LIBXDP_STATIC__ -Wno-pass-failed -o $(BUILD_DIR)/tests/packets tests/packets.c
	$(BUILD_DIR)/tests/packets

# Loader program.
loader: loader_utils
	$(CC) $(INCS) $(FLAGS) $(FLAGS_LOADER) -o $(BUILD_LOADER_DIR)/$(LOADER_OUT) $(LOADER_OBJS) $(LOADER_DIR)/$(LOADER_SRC)

loader_utils: loader_utils_config loader_utils_cli loader_utils_helpers loader_utils_xdp loader_utils_logging loader_utils_stats

loader_utils_config:
	$(CC) $(INCS) $(FLAGS) -c -o $(BUILD_LOADER_DIR)/$(LOADER_UTILS_CONFIG_OBJ) $(LOADER_UTILS_DIR)/$(LOADER_UTILS_CONFIG_SRC)

loader_utils_cli:
	$(CC) $(INCS) $(FLAGS) -c -o $(BUILD_LOADER_DIR)/$(LOADER_UTILS_cli_OBJ) $(LOADER_UTILS_DIR)/$(LOADER_UTILS_cli_SRC)

loader_utils_xdp:
	$(CC) $(INCS) $(FLAGS) -c -o $(BUILD_LOADER_DIR)/$(LOADER_UTILS_XDP_OBJ) $(LOADER_UTILS_DIR)/$(LOADER_UTILS_XDP_SRC)

loader_utils_logging:
	$(CC) $(INCS) $(FLAGS) -c -o $(BUILD_LOADER_DIR)/$(LOADER_UTILS_LOGGING_OBJ) $(LOADER_UTILS_DIR)/$(LOADER_UTILS_LOGGING_SRC)

loader_utils_stats:
	$(CC) $(INCS) $(FLAGS) -c -o $(BUILD_LOADER_DIR)/$(LOADER_UTILS_STATS_OBJ) $(LOADER_UTILS_DIR)/$(LOADER_UTILS_STATS_SRC)

loader_utils_helpers:
	$(CC) $(INCS) $(FLAGS) -c -o $(BUILD_LOADER_DIR)/$(LOADER_UTILS_HELPERS_OBJ) $(LOADER_UTILS_DIR)/$(LOADER_UTILS_HELPERS_SRC)

# XDP program.
xdp:
	$(CC) $(INCS) $(FLAGS) -target bpf -c -o $(BUILD_XDP_DIR)/$(XDP_OBJ) $(XDP_DIR)/$(XDP_SRC)

# Rule add.
rule_add: loader_utils rule_add_utils
	$(CC) $(INCS) $(FLAGS) $(FLAGS_LOADER) -o $(BUILD_RULE_ADD_DIR)/$(RULE_ADD_OUT) $(RULE_OBJS) $(RULE_ADD_OBJS) $(RULE_ADD_DIR)/$(RULE_ADD_SRC)

rule_add_utils: rule_add_utils_cli

rule_add_utils_cli:
	$(CC) $(INCS) $(FLAGS) -c -o $(BUILD_RULE_ADD_DIR)/$(RULE_ADD_UTILS_cli_OBJ) $(RULE_ADD_UTILS_DIR)/$(RULE_ADD_UTILS_cli_SRC)

# Rule delete.
rule_del: loader_utils rule_del_utils
	$(CC) $(INCS) $(FLAGS) $(FLAGS_LOADER) -o $(BUILD_RULE_DEL_DIR)/$(RULE_DEL_OUT) $(RULE_OBJS) $(RULE_DEL_OBJS) $(RULE_DEL_DIR)/$(RULE_DEL_SRC)

rule_del_utils: rule_del_utils_cli

rule_del_utils_cli:
	$(CC) $(INCS) $(FLAGS) -c -o $(BUILD_RULE_DEL_DIR)/$(RULE_DEL_UTILS_cli_OBJ) $(RULE_DEL_UTILS_DIR)/$(RULE_DEL_UTILS_cli_SRC)

# LibXDP chain. We need to install objects here since our program relies on installed object files and such.
libxdp:
	$(MAKE) -C $(XDP_TOOLS_DIR) libxdp

libxdp_install:
	$(MAKE) -C $(LIBBPF_SRC) install
	$(MAKE) -C $(LIBXDP_DIR) install

libxdp_clean:
	$(MAKE) -C $(XDP_TOOLS_DIR) clean
	$(MAKE) -C $(LIBBPF_SRC) clean

install:
	mkdir -p $(ETC_DIR)
	
	cp -n xdpfw.conf.example $(ETC_DIR)/xdpfw.conf

	cp -n other/xdpfw.service /etc/systemd/system/

	cp -f $(BUILD_LOADER_DIR)/$(LOADER_OUT) /usr/bin
	cp -f $(BUILD_RULE_ADD_DIR)/$(RULE_ADD_OUT) /usr/bin
	cp -f $(BUILD_RULE_DEL_DIR)/$(RULE_DEL_OUT) /usr/bin

	cp -f $(BUILD_XDP_DIR)/$(XDP_OBJ) $(ETC_DIR)

clean:	
	find $(BUILD_DIR) -type f ! -name ".*" -exec rm -f {} +
	find $(BUILD_LOADER_DIR) -type f ! -name ".*" -exec rm -f {} +
	find $(BUILD_XDP_DIR) -type f ! -name ".*" -exec rm -f {} +
	find $(BUILD_RULE_ADD_DIR) -type f ! -name ".*" -exec rm -f {} +
	find $(BUILD_RULE_DEL_DIR) -type f ! -name ".*" -exec rm -f {} +

.PHONY: all libxdp test
.DEFAULT: all
