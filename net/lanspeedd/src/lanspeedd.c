#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <net/if.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

#include <json-c/json.h>
#include <libubox/blobmsg_json.h>
#include <libubox/utils.h>
#include <libubox/uloop.h>
#include <libubus.h>
#include <uci.h>

#include "lanspeed_bpf.h"

#define LANSPEED_VERSION "0.1.0"
#define DEFAULT_REFRESH_INTERVAL_MS 1000
#define MIN_REFRESH_INTERVAL_MS 500
#define DEFAULT_MAX_CLIENTS 2048
#define RATE_WINDOW_COUNT 3
#define STALE_CLIENT_MS 5000
#define COMMAND_OUTPUT_LIMIT 4096
#define LANSPEED_BPF_PACKAGE_MARKER "/usr/share/lanspeed/bpf/collector-model.json"
#define LANSPEED_BPF_OBJECT_PATH "/usr/lib/bpf/lanspeed_tc.o"
#define LANSPEED_BPF_SOURCE "lanspeed_tc.bpf.c"
#define LANSPEED_TC_FILTER_PREF 49152
#define LANSPEED_TC_FILTER_HANDLE "0x1eed"
#define LANSPEED_TC_FILTER_OWNER "lanspeed"
#define DAE_FWMARK "0x8000000"
#define DAE_ROUTE_TABLE "2023"
#define CONNTRACK_PROCFS_PATH "/proc/net/nf_conntrack"
#define CONNTRACK_LEGACY_PROCFS_PATH "/proc/net/ip_conntrack"
#define ARP_PROCFS_PATH "/proc/net/arp"
#define CONNTRACK_LINE_MAX 1024
#define IP_STR_LEN 46
#define MAC_STR_LEN 18
#define IFNAME_STR_LEN 32
#define ZONE_STR_LEN 32
#define IDENTITY_KEY_STR_LEN 80
#define MAX_CLIENT_IPS 4
#define OPENCLASH_VALUE_STR_LEN 64
#define HOSTNAME_STR_LEN 64
#define HOSTNAME_CACHE_MAX 1024
#define HOSTNAME_REFRESH_MS 10000
#define DHCP_LEASES_PATH "/tmp/dhcp.leases"
#define HOSTS_DIR "/tmp/hosts"
#define ETC_HOSTS_PATH "/etc/hosts"

static struct ubus_context *ctx;
static struct blob_buf reply;
static int refresh_interval_ms = DEFAULT_REFRESH_INTERVAL_MS;
static int max_clients = DEFAULT_MAX_CLIENTS;
static bool enable_bpf;
static bool enable_conntrack_fallback = true;
static bool refresh_interval_clamped;
static bool rejected_nssifb_collect;

struct arp_entry {
	char ip[IP_STR_LEN];
	char mac[MAC_STR_LEN];
	char ifname[IFNAME_STR_LEN];
	char zone[ZONE_STR_LEN];
};

struct conntrack_client_sample {
	char mac[MAC_STR_LEN];
	char identity_key[IDENTITY_KEY_STR_LEN];
	char zone[ZONE_STR_LEN];
	char ifname[IFNAME_STR_LEN];
	char ips[MAX_CLIENT_IPS][IP_STR_LEN];
	size_t ip_count;
	uint64_t tx_bytes;
	uint64_t rx_bytes;
	uint64_t last_seen_ms;
	uint32_t tcp_conns;
	uint32_t udp_conns;
};

struct conntrack_flow_sample {
	char orig_src[IP_STR_LEN];
	uint64_t orig_bytes;
	uint64_t reply_bytes;
	bool has_orig_src;
	bool has_orig_bytes;
	char protocol[8];
	char tcp_state[16];
	bool assured;
	bool is_tcp;
	bool is_udp;
};

struct conntrack_collect_stats {
	char source_path[PATH_MAX];
	bool procfs_read;
	bool snapshot_pending;
	size_t current_clients;
	size_t emitted_clients;
	size_t skipped_no_arp;
	size_t malformed_lines;
	size_t entries_seen;
	size_t entries_matched;
};

static struct conntrack_client_sample previous_conntrack_samples[DEFAULT_MAX_CLIENTS];
static size_t previous_conntrack_sample_count;
static uint64_t previous_conntrack_snapshot_ms;
static bool previous_conntrack_snapshot_valid;

#define LANSPEED_BPF_IFACE_MAX 16
#define LANSPEED_BPF_IFNAME_LEN IFNAME_STR_LEN

struct bpf_client_sample {
	char mac[MAC_STR_LEN];
	char identity_key[IDENTITY_KEY_STR_LEN];
	char zone[ZONE_STR_LEN];
	char ifname[IFNAME_STR_LEN];
	char ips[MAX_CLIENT_IPS][IP_STR_LEN];
	size_t ip_count;
	uint64_t tx_bytes;
	uint64_t rx_bytes;
	uint64_t last_seen_ms;
};

static char bpf_attach_ifnames[LANSPEED_BPF_IFACE_MAX][LANSPEED_BPF_IFNAME_LEN];
static size_t bpf_attach_ifname_count;
static char bpf_object_runtime_path[PATH_MAX];

/* observe-only ifnames: shown in interfaces throughput card but not BPF-attached */
static char observe_ifnames[LANSPEED_BPF_IFACE_MAX][LANSPEED_BPF_IFNAME_LEN];
static size_t observe_ifname_count;

static struct bpf_client_sample bpf_current_samples[DEFAULT_MAX_CLIENTS];
static size_t bpf_current_sample_count;
static uint64_t bpf_current_snapshot_ms;

static struct bpf_client_sample bpf_previous_samples[DEFAULT_MAX_CLIENTS];
static size_t bpf_previous_sample_count;
static uint64_t bpf_previous_snapshot_ms;
static bool bpf_previous_snapshot_valid;

static struct uloop_timeout bpf_collect_timer;
static bool bpf_runtime_enabled;

struct runtime_probe {
	bool fw4;
	bool nft;
	bool tc;
	bool tc_clsact;
	bool bpf;
	bool bpf_package;
	bool bpf_object;
	bool software_flow_offload;
	bool hardware_flow_offload;
	bool nss_present;
	bool nss_ecm_active;
	bool nss_bridge_mgr;
	bool nss_ifb_active;
	bool nss_ppe_active;
	bool nss_nsm_active;
	bool nss_dp_active;
	bool nss_mcs_active;
	int  nss_ecm_accelerated_connections;
	int  nss_ecm_tcp_connections;
	int  nss_ecm_udp_connections;
	int  nss_ecm_other_connections;
	int  nss_ecm_host_count;
	int  nss_ecm_mapping_count;
	bool fullcone;
	bool nf_conntrack_acct;
	bool nf_conntrack_acct_present;
	bool flowtable_counter;
	bool existing_tc_filters;
	bool ifb;
	bool sqm;
	bool qosify;
	bool openclash;
	bool openclash_fake_ip;
	bool openclash_tun_mix;
	bool openclash_redirect_dns;
	bool openclash_dnsmasq_chain;
	bool openclash_dns_chain_incomplete;
	bool openclash_router_self_proxy;
	bool openclash_udp_proxy;
	bool openclash_ipv6;
	bool dae;
	bool daed;
	bool dae_config;
	bool daed_config;
	bool dae_service;
	bool daed_service;
	bool dae_iface;
	bool dae_peer_iface;
	bool dae_tc_filters;
	bool dae_fwmark;
	bool dae_route_table;
	bool dae_dns_udp53;
	bool tc_filter_conflict;
	bool homeproxy;
	bool nlbwmon;
	bool lan_bridge;
	bool vlan;
	bool wlan;
	bool ubus;
	bool lan_edge;
	bool safe_attach;
	bool bpf_runtime_metrics;
	bool map_full;
	bool probe_error;
	bool lan_probe_error;
	struct json_object *warnings;
	struct json_object *conflicts;
	struct json_object *evidence;
	struct json_object *tc_filters;
	struct json_object *commands;
	struct json_object *files;
	struct json_object *uci;
	struct json_object *ubus_evidence;
	struct json_object *source_commands;
	struct json_object *source_files;
	struct json_object *source_uci;
	struct json_object *source_ubus;
	char openclash_en_mode[OPENCLASH_VALUE_STR_LEN];
	char openclash_stack_type[OPENCLASH_VALUE_STR_LEN];
};

static void add_string_unique(struct json_object *array, const char *value)
{
	size_t i;

	if (!array || !value)
		return;

	for (i = 0; i < json_object_array_length(array); i++) {
		struct json_object *entry = json_object_array_get_idx(array, i);

		if (entry && !strcmp(json_object_get_string(entry), value))
			return;
	}

	json_object_array_add(array, json_object_new_string(value));
}

static void add_warning(struct runtime_probe *probe, const char *warning)
{
	add_string_unique(probe->warnings, warning);
}

static void add_conflict(struct runtime_probe *probe, const char *id,
				 const char *severity, const char *message)
{
	struct json_object *conflict = json_object_new_object();

	json_object_object_add(conflict, "id", json_object_new_string(id));
	json_object_object_add(conflict, "severity", json_object_new_string(severity));
	json_object_object_add(conflict, "message", json_object_new_string(message));
	json_object_array_add(probe->conflicts, conflict);
}

static bool file_exists(const char *path)
{
	return access(path, F_OK) == 0;
}

static bool dir_has_entries(const char *path)
{
	DIR *dir = opendir(path);
	struct dirent *entry;
	bool found = false;

	if (!dir)
		return false;

	while ((entry = readdir(dir)) != NULL) {
		if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
			continue;

		found = true;
		break;
	}

	closedir(dir);
	return found;
}

static bool read_file_trimmed(const char *path, char *buffer, size_t size)
{
	FILE *file;
	size_t len;

	if (!buffer || !size)
		return false;

	buffer[0] = '\0';
	file = fopen(path, "r");
	if (!file)
		return false;

	if (!fgets(buffer, size, file)) {
		fclose(file);
		return false;
	}

	fclose(file);
	len = strlen(buffer);
	while (len > 0 && isspace((unsigned char)buffer[len - 1]))
		buffer[--len] = '\0';

	return true;
}

static bool command_exists(const char *name)
{
	const char *path_env;
	char *paths;
	char *saveptr = NULL;
	char *dir;
	char candidate[PATH_MAX];
	bool found = false;

	if (!name || !name[0])
		return false;

	if (strchr(name, '/'))
		return access(name, X_OK) == 0;

	path_env = getenv("PATH");
	if (!path_env || !path_env[0])
		path_env = "/sbin:/bin:/usr/sbin:/usr/bin";

	paths = strdup(path_env);
	if (!paths)
		return false;

	for (dir = strtok_r(paths, ":", &saveptr); dir; dir = strtok_r(NULL, ":", &saveptr)) {
		if (!dir[0])
			continue;

		if (snprintf(candidate, sizeof(candidate), "%s/%s", dir, name) >= (int)sizeof(candidate))
			continue;

		if (access(candidate, X_OK) == 0) {
			found = true;
			break;
		}
	}

	free(paths);
	return found;
}

static int run_command_capture(const char *command, char *buffer, size_t size)
{
	FILE *pipe;
	size_t used = 0;
	int status;

	if (!buffer || !size)
		return -1;

	buffer[0] = '\0';
	pipe = popen(command, "r");
	if (!pipe)
		return -1;

	while (used + 1 < size && fgets(buffer + used, size - used, pipe))
		used = strlen(buffer);

	status = pclose(pipe);
	if (status == -1)
		return -1;

	if (WIFEXITED(status))
		return WEXITSTATUS(status);

	return status;
}

static void add_source(struct json_object *array, const char *source)
{
	add_string_unique(array, source);
}

static void add_command_evidence(struct runtime_probe *probe, const char *name,
					 bool available)
{
	struct json_object *entry = json_object_new_object();
	char source[64];

	snprintf(source, sizeof(source), "command:%s", name);
	add_source(probe->source_commands, source);
	json_object_object_add(entry, "source", json_object_new_string(source));
	json_object_object_add(entry, "available", json_object_new_boolean(available));
	json_object_object_add(probe->commands, name, entry);
}

static void add_command_probe_evidence(struct runtime_probe *probe, const char *key,
				       const char *command, int exit_code, const char *summary,
				       bool supported)
{
	struct json_object *entry = json_object_new_object();
	char source[128];

	snprintf(source, sizeof(source), "command:%s", key);
	add_source(probe->source_commands, source);
	json_object_object_add(entry, "source", json_object_new_string(source));
	json_object_object_add(entry, "command", json_object_new_string(command));
	json_object_object_add(entry, "exit_code", json_object_new_int(exit_code));
	json_object_object_add(entry, "supported", json_object_new_boolean(supported));
	if (summary)
		json_object_object_add(entry, "summary", json_object_new_string(summary));
	json_object_object_add(probe->commands, key, entry);
}

static void add_file_evidence(struct runtime_probe *probe, const char *key,
			      const char *path, bool present, const char *value)
{
	struct json_object *entry = json_object_new_object();
	char source[PATH_MAX + 16];

	snprintf(source, sizeof(source), "file:%s", path);
	add_source(probe->source_files, source);
	json_object_object_add(entry, "source", json_object_new_string(source));
	json_object_object_add(entry, "path", json_object_new_string(path));
	json_object_object_add(entry, "present", json_object_new_boolean(present));
	if (value)
		json_object_object_add(entry, "value", json_object_new_string(value));
	json_object_object_add(probe->files, key, entry);
}

static void add_uci_evidence(struct runtime_probe *probe, const char *key,
			     const char *package, bool loaded)
{
	struct json_object *entry = json_object_new_object();
	char source[128];

	snprintf(source, sizeof(source), "uci:%s", package);
	add_source(probe->source_uci, source);
	json_object_object_add(entry, "source", json_object_new_string(source));
	json_object_object_add(entry, "package", json_object_new_string(package));
	json_object_object_add(entry, "loaded", json_object_new_boolean(loaded));
	json_object_object_add(probe->uci, key, entry);
}

static void add_ubus_evidence(struct runtime_probe *probe, const char *key,
			      const char *object, bool attempted, int exit_code,
			      const char *summary)
{
	struct json_object *entry = json_object_new_object();
	char source[128];

	snprintf(source, sizeof(source), "ubus:%s", object);
	add_source(probe->source_ubus, source);
	json_object_object_add(entry, "source", json_object_new_string(source));
	json_object_object_add(entry, "object", json_object_new_string(object));
	json_object_object_add(entry, "attempted", json_object_new_boolean(attempted));
	json_object_object_add(entry, "exit_code", json_object_new_int(exit_code));
	if (summary)
		json_object_object_add(entry, "summary", json_object_new_string(summary));
	json_object_object_add(probe->ubus_evidence, key, entry);
}

static bool uci_bool_value(const char *value)
{
	return value && (!strcmp(value, "1") || !strcmp(value, "true") ||
		       !strcmp(value, "on") || !strcmp(value, "yes"));
}

static bool value_contains_token(const char *value, const char *token)
{
	return value && token && strstr(value, token) != NULL;
}

static bool ifname_is_excluded_identity_source(const char *ifname)
{
	if (!ifname || !ifname[0])
		return false;

	return !strcmp(ifname, "dae0") || !strcmp(ifname, "dae0peer") ||
	       !strncmp(ifname, "tun", 3) || !strncmp(ifname, "ppp", 3) ||
	       !strncmp(ifname, "wg", 2);
}

static bool line_contains_lanspeed_filter_conflict(const char *line)
{
	return line && strstr(line, "pref 49152") != NULL &&
	       (strstr(line, "handle 0x1eed") != NULL || strstr(line, "handle 1eed") != NULL) &&
	       strstr(line, LANSPEED_TC_FILTER_OWNER) == NULL;
}

static const char *tc_filter_owner_from_line(const char *line)
{
	if (!line)
		return "unknown";
	if (strstr(line, LANSPEED_TC_FILTER_OWNER))
		return LANSPEED_TC_FILTER_OWNER;
	if (strstr(line, "dae") || strstr(line, "daed") || strstr(line, "dae0"))
		return "dae";
	if (strstr(line, "sqm"))
		return "sqm";
	if (strstr(line, "qosify"))
		return "qosify";
	if (strstr(line, "ifb"))
		return "ifb";
	return "unknown";
}

static void add_detected_tc_filter(struct runtime_probe *probe, const char *ifname,
					  const char *direction, const char *pref,
					  const char *handle, const char *owner,
					  const char *source)
{
	struct json_object *filter;

	if (!probe->tc_filters)
		return;

	filter = json_object_new_object();
	json_object_object_add(filter, "interface", json_object_new_string(ifname ? ifname : "unknown"));
	json_object_object_add(filter, "direction", json_object_new_string(direction ? direction : "unknown"));
	json_object_object_add(filter, "pref", json_object_new_string(pref ? pref : "unknown"));
	json_object_object_add(filter, "handle", json_object_new_string(handle ? handle : "unknown"));
	json_object_object_add(filter, "owner", json_object_new_string(owner ? owner : "unknown"));
	json_object_object_add(filter, "source", json_object_new_string(source ? source : "tc_filter_show"));
	json_object_array_add(probe->tc_filters, filter);
}

static void inspect_tc_filter_lines(struct runtime_probe *probe, const char *ifname,
					   const char *direction, const char *output)
{
	char buffer[COMMAND_OUTPUT_LIMIT];
	char *saveptr = NULL;
	char *line;

	if (!output || !output[0])
		return;

	snprintf(buffer, sizeof(buffer), "%s", output);
	for (line = strtok_r(buffer, "\n", &saveptr); line;
	     line = strtok_r(NULL, "\n", &saveptr)) {
		char *pref_pos = strstr(line, "pref ");
		char *handle_pos = strstr(line, "handle ");
		char pref[32] = "unknown";
		char handle[32] = "unknown";
		const char *owner;

		if (pref_pos)
			sscanf(pref_pos, "pref %31s", pref);
		if (handle_pos)
			sscanf(handle_pos, "handle %31s", handle);

		if (strstr(line, "filter") == NULL && strstr(line, "bpf") == NULL)
			continue;

		owner = tc_filter_owner_from_line(line);
		if (!strcmp(owner, "dae")) {
			probe->dae_tc_filters = true;
			probe->dae = true;
		}
		if (line_contains_lanspeed_filter_conflict(line))
			probe->tc_filter_conflict = true;

		add_detected_tc_filter(probe, ifname, direction, pref, handle, owner, "tc_filter_show");
	}
}

static bool openclash_mode_is_fake_ip(const char *mode)
{
	return value_contains_token(mode, "fake-ip") || value_contains_token(mode, "fake_ip");
}

static bool openclash_mode_is_tun_mix(const char *mode)
{
	return value_contains_token(mode, "tun") || value_contains_token(mode, "mix") ||
	       value_contains_token(mode, "TUN") || value_contains_token(mode, "Mix");
}

static void add_uci_option_evidence(struct runtime_probe *probe, const char *key,
					   const char *package_name, const char *section,
					   const char *option, const char *value, bool present)
{
	struct json_object *entry = json_object_new_object();
	char source[160];

	snprintf(source, sizeof(source), "uci:%s.%s.%s", package_name, section, option);
	add_source(probe->source_uci, source);
	json_object_object_add(entry, "source", json_object_new_string(source));
	json_object_object_add(entry, "package", json_object_new_string(package_name));
	json_object_object_add(entry, "section", json_object_new_string(section));
	json_object_object_add(entry, "option", json_object_new_string(option));
	json_object_object_add(entry, "present", json_object_new_boolean(present));
	if (value)
		json_object_object_add(entry, "value", json_object_new_string(value));
	json_object_object_add(probe->uci, key, entry);
}

static const char *enabled_state(bool enabled)
{
	return enabled ? "enabled" : "disabled";
}

static const char *present_state(bool present)
{
	return present ? "present" : "missing";
}

static void inspect_firewall_uci(struct runtime_probe *probe)
{
	struct uci_context *uci = uci_alloc_context();
	struct uci_package *package = NULL;
	struct uci_element *element;
	bool loaded = false;

	if (!uci) {
		add_uci_evidence(probe, "firewall", "firewall", false);
		probe->probe_error = true;
		add_warning(probe, "probe_error");
		return;
	}

	loaded = uci_load(uci, "firewall", &package) == 0 && package;
	add_uci_evidence(probe, "firewall", "firewall", loaded);
	if (!loaded) {
		uci_free_context(uci);
		return;
	}

	uci_foreach_element(&package->sections, element) {
		struct uci_section *section = uci_to_section(element);

		if (strcmp(section->type, "defaults"))
			continue;

		if (uci_bool_value(uci_lookup_option_string(uci, section, "flow_offloading")))
			probe->software_flow_offload = true;
		if (uci_bool_value(uci_lookup_option_string(uci, section, "flow_offloading_hw")))
			probe->hardware_flow_offload = true;
		if (uci_bool_value(uci_lookup_option_string(uci, section, "fullcone")))
			probe->fullcone = true;
	}

	uci_unload(uci, package);
	uci_free_context(uci);
}

static void inspect_package_uci(struct runtime_probe *probe, const char *key,
				const char *package_name, bool *present)
{
	struct uci_context *uci = uci_alloc_context();
	struct uci_package *package = NULL;
	bool loaded = false;

	if (present)
		*present = false;

	if (!uci) {
		add_uci_evidence(probe, key, package_name, false);
		probe->probe_error = true;
		add_warning(probe, "probe_error");
		return;
	}

	loaded = uci_load(uci, package_name, &package) == 0 && package;
	add_uci_evidence(probe, key, package_name, loaded);
	if (loaded && present)
		*present = true;

	if (loaded)
		uci_unload(uci, package);
	uci_free_context(uci);
}

static void inspect_openclash_uci_options(struct runtime_probe *probe)
{
	struct uci_context *uci = uci_alloc_context();
	struct uci_package *package = NULL;
	struct uci_element *element;
	bool loaded = false;
	bool found_section = false;

	if (!uci) {
		probe->probe_error = true;
		add_warning(probe, "probe_error");
		return;
	}

	loaded = uci_load(uci, "openclash", &package) == 0 && package;
	if (!loaded) {
		uci_free_context(uci);
		return;
	}

	uci_foreach_element(&package->sections, element) {
		struct uci_section *section = uci_to_section(element);
		const char *en_mode = uci_lookup_option_string(uci, section, "en_mode");
		const char *redirect_dns = uci_lookup_option_string(uci, section, "enable_redirect_dns");
		const char *router_self = uci_lookup_option_string(uci, section, "router_self_proxy");
		const char *udp_proxy = uci_lookup_option_string(uci, section, "enable_udp_proxy");
		const char *stack_type = uci_lookup_option_string(uci, section, "stack_type");
		const char *ipv6 = uci_lookup_option_string(uci, section, "ipv6_enable");

		if (!en_mode && !redirect_dns && !router_self && !udp_proxy && !stack_type && !ipv6)
			continue;

		found_section = true;
		if (en_mode) {
			snprintf(probe->openclash_en_mode, sizeof(probe->openclash_en_mode), "%s", en_mode);
			probe->openclash_fake_ip = openclash_mode_is_fake_ip(en_mode);
			probe->openclash_tun_mix = openclash_mode_is_tun_mix(en_mode);
		}
		if (stack_type) {
			snprintf(probe->openclash_stack_type, sizeof(probe->openclash_stack_type), "%s", stack_type);
			if (openclash_mode_is_tun_mix(stack_type))
				probe->openclash_tun_mix = true;
		}
		if (redirect_dns)
			probe->openclash_redirect_dns = uci_bool_value(redirect_dns);
		if (router_self)
			probe->openclash_router_self_proxy = uci_bool_value(router_self);
		if (udp_proxy)
			probe->openclash_udp_proxy = uci_bool_value(udp_proxy);
		if (ipv6)
			probe->openclash_ipv6 = uci_bool_value(ipv6);

		add_uci_option_evidence(probe, "openclash_en_mode", "openclash",
					section->e.name, "en_mode", en_mode, en_mode != NULL);
		add_uci_option_evidence(probe, "openclash_enable_redirect_dns", "openclash",
					section->e.name, "enable_redirect_dns", redirect_dns, redirect_dns != NULL);
		add_uci_option_evidence(probe, "openclash_router_self_proxy", "openclash",
					section->e.name, "router_self_proxy", router_self, router_self != NULL);
		add_uci_option_evidence(probe, "openclash_enable_udp_proxy", "openclash",
					section->e.name, "enable_udp_proxy", udp_proxy, udp_proxy != NULL);
		add_uci_option_evidence(probe, "openclash_stack_type", "openclash",
					section->e.name, "stack_type", stack_type, stack_type != NULL);
		add_uci_option_evidence(probe, "openclash_ipv6_enable", "openclash",
					section->e.name, "ipv6_enable", ipv6, ipv6 != NULL);
		break;
	}

	if (!found_section)
		add_uci_option_evidence(probe, "openclash_options", "openclash", "unknown",
					"en_mode", NULL, false);

	uci_unload(uci, package);
	uci_free_context(uci);
}

static void inspect_dnsmasq_openclash_chain(struct runtime_probe *probe)
{
	struct uci_context *uci = uci_alloc_context();
	struct uci_package *package = NULL;
	struct uci_element *section_element;
	struct uci_element *option_element;
	bool loaded = false;
	bool chain_complete = false;

	if (!probe->openclash)
		return;

	if (!uci) {
		add_uci_evidence(probe, "dhcp", "dhcp", false);
		probe->probe_error = true;
		add_warning(probe, "probe_error");
		return;
	}

	loaded = uci_load(uci, "dhcp", &package) == 0 && package;
	add_uci_evidence(probe, "dhcp", "dhcp", loaded);
	if (!loaded) {
		uci_free_context(uci);
		return;
	}

	uci_foreach_element(&package->sections, section_element) {
		struct uci_section *section = uci_to_section(section_element);

		uci_foreach_element(&section->options, option_element) {
			struct uci_option *option = uci_to_option(option_element);

			if (option->type == UCI_TYPE_STRING) {
				const char *value = option->v.string;
				if (value && strstr(value, "127.0.0.1#7874"))
					chain_complete = true;
			} else if (option->type == UCI_TYPE_LIST) {
				struct uci_element *list_element;

				uci_foreach_element(&option->v.list, list_element) {
					if (strstr(list_element->name, "127.0.0.1#7874"))
						chain_complete = true;
				}
			}
		}
	}

	probe->openclash_dnsmasq_chain = chain_complete;
	if (probe->openclash_redirect_dns && !probe->openclash_dnsmasq_chain)
		probe->openclash_dns_chain_incomplete = true;

	uci_unload(uci, package);
	uci_free_context(uci);
}

static void inspect_command_capabilities(struct runtime_probe *probe)
{
	probe->fw4 = command_exists("fw4");
	probe->nft = command_exists("nft");
	probe->tc = command_exists("tc");
	probe->qosify = command_exists("qosify");
	probe->ubus = command_exists("ubus");

	add_command_evidence(probe, "fw4", probe->fw4);
	add_command_evidence(probe, "nft", probe->nft);
	add_command_evidence(probe, "tc", probe->tc);
	add_command_evidence(probe, "qosify", probe->qosify);
	add_command_evidence(probe, "ubus", probe->ubus);

	if (!probe->tc)
		add_warning(probe, "tc_missing");
}

static void inspect_tc(struct runtime_probe *probe)
{
	char output[COMMAND_OUTPUT_LIMIT];
	int exit_code;

	if (!probe->tc)
		return;

	exit_code = run_command_capture("tc filter help 2>&1", output, sizeof(output));
	probe->bpf = strstr(output, "bpf") != NULL || strstr(output, "BPF") != NULL;
	add_command_probe_evidence(probe, "tc_filter_help", "tc filter help", exit_code,
				   probe->bpf ? "bpf filter support advertised" : "bpf filter support not advertised",
				   probe->bpf);
	if (exit_code != 0 && !output[0]) {
		probe->probe_error = true;
		add_warning(probe, "probe_error");
	}

	exit_code = run_command_capture("tc qdisc help 2>&1", output, sizeof(output));
	probe->tc_clsact = strstr(output, "clsact") != NULL;
	add_command_probe_evidence(probe, "tc_qdisc_help", "tc qdisc help", exit_code,
				   probe->tc_clsact ? "clsact qdisc support advertised" : "clsact qdisc support not advertised",
				   probe->tc_clsact);
	if (exit_code != 0 && !output[0]) {
		probe->probe_error = true;
		add_warning(probe, "probe_error");
	}

	/* Scan tc filters on every configured LAN-edge interface instead of
	 * assuming br-lan. This matters on DSA / single-NIC / VLAN / AP-only
	 * deployments where br-lan may not exist. If no interface is
	 * configured yet, fall back to br-lan / eth0 so the probe still
	 * surfaces something useful during first install. */
	{
		const char *scan_list[LANSPEED_BPF_IFACE_MAX + 4];
		size_t scan_count = 0;
		size_t idx;

		for (idx = 0; idx < bpf_attach_ifname_count &&
			      scan_count < sizeof(scan_list) / sizeof(scan_list[0]); idx++)
			scan_list[scan_count++] = bpf_attach_ifnames[idx];
		for (idx = 0; idx < observe_ifname_count &&
			      scan_count < sizeof(scan_list) / sizeof(scan_list[0]); idx++)
			scan_list[scan_count++] = observe_ifnames[idx];
		if (!scan_count) {
			/* discovery fallback for a fresh install */
			if (file_exists("/sys/class/net/br-lan"))
				scan_list[scan_count++] = "br-lan";
			if (file_exists("/sys/class/net/eth0") &&
			    scan_count < sizeof(scan_list) / sizeof(scan_list[0]))
				scan_list[scan_count++] = "eth0";
		}

		probe->existing_tc_filters = false;
		for (idx = 0; idx < scan_count; idx++) {
			const char *dev = scan_list[idx];
			char cmd[128];
			char evidence_key[64];
			const char *direction[2] = { "ingress", "egress" };
			size_t dir_idx;

			for (dir_idx = 0; dir_idx < 2; dir_idx++) {
				snprintf(cmd, sizeof(cmd),
				         "tc filter show dev %s %s 2>&1",
				         dev, direction[dir_idx]);
				exit_code = run_command_capture(cmd, output, sizeof(output));
				if (exit_code == 0 && output[0]) {
					if (strstr(output, "filter") != NULL || strstr(output, "bpf") != NULL)
						probe->existing_tc_filters = true;
					inspect_tc_filter_lines(probe, dev, direction[dir_idx], output);
				} else if (exit_code != 0 &&
				           strstr(output, "Cannot") == NULL &&
				           strstr(output, "No such") == NULL) {
					probe->probe_error = true;
					probe->lan_probe_error = true;
					add_warning(probe, "probe_error");
				}
				snprintf(evidence_key, sizeof(evidence_key),
				         "tc_filter_show_%s_%s", dev, direction[dir_idx]);
				add_command_probe_evidence(probe, evidence_key, cmd, exit_code,
					probe->existing_tc_filters
						? "existing filters detected on at least one configured device"
						: "no existing filters on this device",
					probe->existing_tc_filters);
			}
		}
	}

	if (!probe->bpf)
		add_warning(probe, "bpf_unsupported");
	if (!probe->tc_clsact)
		add_warning(probe, "tc_clsact_unsupported");
	if (probe->existing_tc_filters)
		add_warning(probe, "existing_tc_filters_detected");
}

static void inspect_dae_runtime(struct runtime_probe *probe)
{
	char output[COMMAND_OUTPUT_LIMIT];
	int exit_code;

	probe->dae_config = file_exists("/etc/config/dae");
	probe->daed_config = file_exists("/etc/config/daed");
	probe->dae_iface = file_exists("/sys/class/net/dae0");
	probe->dae_peer_iface = file_exists("/sys/class/net/dae0peer");

	if (probe->dae_config || probe->daed_config || probe->dae_iface ||
	    probe->dae_peer_iface || probe->dae_tc_filters)
		probe->dae = true;

	if (probe->ubus) {
		exit_code = run_command_capture("ubus call service list '{\"name\":\"dae\"}' 2>&1", output, sizeof(output));
		probe->dae_service = exit_code == 0 && strstr(output, "dae") != NULL;
		add_ubus_evidence(probe, "service_dae", "service.dae", true, exit_code,
				  probe->dae_service ? "dae service present" : "dae service not present");

		exit_code = run_command_capture("ubus call service list '{\"name\":\"daed\"}' 2>&1", output, sizeof(output));
		probe->daed_service = exit_code == 0 && strstr(output, "daed") != NULL;
		add_ubus_evidence(probe, "service_daed", "service.daed", true, exit_code,
				  probe->daed_service ? "daed service present" : "daed service not present");
	} else {
		add_ubus_evidence(probe, "service_dae", "service.dae", false, -1, "ubus command missing");
		add_ubus_evidence(probe, "service_daed", "service.daed", false, -1, "ubus command missing");
	}

	if (probe->dae_service || probe->daed_service)
		probe->dae = true;

	if (probe->tc) {
		exit_code = run_command_capture("tc filter show dev dae0 ingress 2>&1", output, sizeof(output));
		if (exit_code == 0 && output[0])
			inspect_tc_filter_lines(probe, "dae0", "ingress", output);
		exit_code = run_command_capture("tc filter show dev dae0 egress 2>&1", output, sizeof(output));
		if (exit_code == 0 && output[0])
			inspect_tc_filter_lines(probe, "dae0", "egress", output);
		exit_code = run_command_capture("tc filter show dev dae0peer ingress 2>&1", output, sizeof(output));
		if (exit_code == 0 && output[0])
			inspect_tc_filter_lines(probe, "dae0peer", "ingress", output);
	}

	exit_code = run_command_capture("ip rule show 2>&1", output, sizeof(output));
	if (exit_code == 0 && output[0]) {
		probe->dae_fwmark = strstr(output, DAE_FWMARK) != NULL;
		if (probe->dae_fwmark)
			probe->dae = true;
		add_command_probe_evidence(probe, "ip_rule_show", "ip rule show", exit_code,
					   probe->dae_fwmark ? "dae fwmark detected" : "dae fwmark not detected",
					   probe->dae_fwmark);
	}

	exit_code = run_command_capture("ip route show table 2023 2>&1", output, sizeof(output));
	if (exit_code == 0 && output[0]) {
		probe->dae_route_table = strstr(output, "dae0") != NULL || strstr(output, "default") != NULL;
		if (probe->dae_route_table)
			probe->dae = true;
		add_command_probe_evidence(probe, "ip_route_table_2023", "ip route show table 2023", exit_code,
					   probe->dae_route_table ? "dae route table detected" : "dae route table not detected",
					   probe->dae_route_table);
	}

	if (probe->nft) {
		exit_code = run_command_capture("nft list ruleset 2>&1", output, sizeof(output));
		if (exit_code == 0 && output[0]) {
			probe->dae_dns_udp53 = (strstr(output, "udp dport 53") != NULL || strstr(output, "dport 53") != NULL) &&
					       (strstr(output, "dae") != NULL || strstr(output, DAE_FWMARK) != NULL);
			if (probe->dae_dns_udp53)
				probe->dae = true;
			add_command_probe_evidence(probe, "nft_dae_dns_udp53", "nft list ruleset", exit_code,
						   probe->dae_dns_udp53 ? "dae UDP/53 handling detected" : "dae UDP/53 handling not detected",
						   probe->dae_dns_udp53);
		}
	}

	if (probe->tc_filter_conflict) {
		add_warning(probe, "tc_filter_conflict");
		add_conflict(probe, "tc_filter_conflict", "warning",
			     "An existing tc filter already uses lanspeed pref/handle; lanspeedd will not overwrite it.");
	}
}

static void inspect_bpf_assets(struct runtime_probe *probe)
{
	probe->bpf_package = file_exists(LANSPEED_BPF_PACKAGE_MARKER);
	probe->bpf_object = file_exists(LANSPEED_BPF_OBJECT_PATH);

	add_file_evidence(probe, "lanspeedd_bpf_package", LANSPEED_BPF_PACKAGE_MARKER,
			  probe->bpf_package, NULL);
	add_file_evidence(probe, "lanspeedd_bpf_object", LANSPEED_BPF_OBJECT_PATH,
			  probe->bpf_object, NULL);

	if (!enable_bpf)
		add_warning(probe, "bpf_disabled");
	if (!probe->bpf_package)
		add_warning(probe, "bpf_optional_package_missing");
	if (!probe->bpf_object)
		add_warning(probe, "bpf_object_missing");
}

static bool bpf_runtime_metrics_available(const struct runtime_probe *probe)
{
	uint64_t freshness;

	if (!enable_bpf || !bpf_runtime_enabled)
		return false;
	if (probe && !probe->safe_attach)
		return false;

	freshness = (uint64_t)refresh_interval_ms * 3ULL;
	if (freshness == 0)
		freshness = (uint64_t)DEFAULT_REFRESH_INTERVAL_MS * 3ULL;
	return lanspeed_bpf_runtime_ok(freshness);
}

static void inspect_collector_attach_model(struct runtime_probe *probe)
{
	probe->lan_edge = probe->lan_bridge || probe->vlan || probe->wlan;
	probe->map_full = max_clients < 1;
	probe->safe_attach = enable_bpf && probe->tc && probe->tc_clsact && probe->bpf &&
			     probe->bpf_package && probe->bpf_object && probe->lan_edge &&
			     !probe->map_full && !probe->tc_filter_conflict;
	probe->bpf_runtime_metrics = bpf_runtime_metrics_available(probe);

	if (!probe->lan_edge)
		add_warning(probe, "lan_edge_missing");
	if (enable_bpf && !probe->safe_attach)
		add_warning(probe, "unsafe_attach");
	if (probe->map_full)
		add_warning(probe, "map_full");
	if (enable_bpf && probe->safe_attach && !probe->bpf_runtime_metrics) {
		add_warning(probe, "bpf_runtime_loader_unavailable");
		add_warning(probe, "live_metrics_unavailable");
	}
}

static void inspect_flowtable_counter(struct runtime_probe *probe)
{
	char output[COMMAND_OUTPUT_LIMIT];
	int exit_code;
	bool proc_present = file_exists("/proc/net/nf_flowtable");
	bool debug_present = file_exists("/sys/kernel/debug/netfilter/nf_flowtable");

	add_file_evidence(probe, "flowtable_proc", "/proc/net/nf_flowtable", proc_present, NULL);
	add_file_evidence(probe, "flowtable_debug", "/sys/kernel/debug/netfilter/nf_flowtable", debug_present, NULL);

	if (!probe->nft) {
		probe->flowtable_counter = false;
		add_warning(probe, "flowtable_counter_probe_unavailable");
		add_warning(probe, "flowtable_counter_missing");
		return;
	}

	/*
	 * Use `nft list flowtables` instead of `nft list ruleset`: the latter
	 * can easily exceed the 4 KiB command output buffer on real routers
	 * (OpenClash + fullcone + DNAT rules push the ruleset past 30 KiB),
	 * truncating the flowtable block and causing a false negative. The
	 * flowtables subcommand emits only flowtable definitions and is
	 * always small.
	 */
	exit_code = run_command_capture("nft list flowtables 2>&1", output, sizeof(output));
	probe->flowtable_counter = exit_code == 0 && strstr(output, "flowtable") != NULL && strstr(output, "counter") != NULL;
	add_command_probe_evidence(probe, "nft_list_flowtables", "nft list flowtables", exit_code,
				   probe->flowtable_counter ? "flowtable counter detected" : "flowtable counter not detected",
				   probe->flowtable_counter);
	if (exit_code == 0 && !probe->flowtable_counter)
		add_warning(probe, "flowtable_counter_missing");
	if (exit_code != 0) {
		probe->probe_error = true;
		add_warning(probe, "probe_error");
	}
}

static void inspect_files(struct runtime_probe *probe)
{
	char value[64];
	bool present;

	present = read_file_trimmed("/proc/sys/net/netfilter/nf_conntrack_acct", value, sizeof(value));
	probe->nf_conntrack_acct_present = present;
	probe->nf_conntrack_acct = present && !strcmp(value, "1");
	add_file_evidence(probe, "nf_conntrack_acct", "/proc/sys/net/netfilter/nf_conntrack_acct", present, present ? value : NULL);
	if (present && !probe->nf_conntrack_acct) {
		add_warning(probe, "nf_conntrack_acct_disabled");
		add_warning(probe, "conntrack_acct_disabled");
	}

	inspect_flowtable_counter(probe);

	probe->ifb = file_exists("/sys/class/net/ifb0") || dir_has_entries("/sys/class/net/ifb");
	add_file_evidence(probe, "ifb0", "/sys/class/net/ifb0", file_exists("/sys/class/net/ifb0"), NULL);

	/* lan_bridge: true if any configured collect/observe interface is
	 * a bridge, or (first-install fallback) br-lan exists. */
	{
		size_t idx;
		probe->lan_bridge = false;
		for (idx = 0; idx < bpf_attach_ifname_count && !probe->lan_bridge; idx++) {
			char path[PATH_MAX];
			snprintf(path, sizeof(path), "/sys/class/net/%s/bridge",
			         bpf_attach_ifnames[idx]);
			if (file_exists(path))
				probe->lan_bridge = true;
		}
		for (idx = 0; idx < observe_ifname_count && !probe->lan_bridge; idx++) {
			char path[PATH_MAX];
			snprintf(path, sizeof(path), "/sys/class/net/%s/bridge",
			         observe_ifnames[idx]);
			if (file_exists(path))
				probe->lan_bridge = true;
		}
		if (!probe->lan_bridge)
			probe->lan_bridge = file_exists("/sys/class/net/br-lan/bridge");
	}
	add_file_evidence(probe, "lan_bridge", "any_configured_device/bridge",
	                  probe->lan_bridge, NULL);

	probe->vlan = file_exists("/proc/net/vlan/config");
	add_file_evidence(probe, "vlan", "/proc/net/vlan/config", probe->vlan, NULL);

	probe->wlan = dir_has_entries("/sys/class/ieee80211") || file_exists("/sys/class/net/wlan0");
	add_file_evidence(probe, "wlan", "/sys/class/ieee80211", dir_has_entries("/sys/class/ieee80211"), NULL);

	add_file_evidence(probe, "openclash_config", "/etc/config/openclash", file_exists("/etc/config/openclash"), NULL);
	add_file_evidence(probe, "dae_config", "/etc/config/dae", file_exists("/etc/config/dae"), NULL);
	add_file_evidence(probe, "daed_config", "/etc/config/daed", file_exists("/etc/config/daed"), NULL);
	add_file_evidence(probe, "homeproxy_config", "/etc/config/homeproxy", file_exists("/etc/config/homeproxy"), NULL);
	add_file_evidence(probe, "nlbwmon_config", "/etc/config/nlbwmon", file_exists("/etc/config/nlbwmon"), NULL);
}

static void inspect_ubus(struct runtime_probe *probe)
{
	char output[COMMAND_OUTPUT_LIMIT];
	int exit_code;

	if (!probe->ubus) {
		add_ubus_evidence(probe, "network_lan", "network.interface.lan", false, -1, "ubus command missing");
		return;
	}

	exit_code = run_command_capture("ubus call network.interface.lan status 2>&1", output, sizeof(output));
	add_ubus_evidence(probe, "network_lan", "network.interface.lan", true, exit_code,
			  exit_code == 0 ? "status available" : "status unavailable");
	if (exit_code != 0) {
		probe->probe_error = true;
		probe->lan_probe_error = true;
		add_warning(probe, "probe_error");
		add_warning(probe, "lan_topology_probe_error");
	}
}

static void inspect_nss(struct runtime_probe *probe)
{
	/* Qualcomm NSS cores sit between the PHY and the Linux kernel on
	 * IPQ807x / IPQ60xx / IPQ50xx platforms. Once ECM (Enhanced
	 * Connection Manager) pushes a flow into NSS hardware, subsequent
	 * packets bypass the CPU entirely: our tc clsact / BPF filter
	 * attaches at the Linux edge, so it only sees slow-path traffic
	 * (control plane, first packets, broadcast, exceptions).
	 *
	 * /proc/net/nf_conntrack stays usable because ECM periodically syncs
	 * per-flow byte counters back into conntrack, at ECM sync cadence
	 * rather than true per-packet precision.
	 *
	 * /sys/class/net/<if>/statistics/{rx,tx}_bytes stays accurate
	 * because NSS drivers push those counters through the kernel netdev
	 * structure even for hardware-offloaded paths, so interface
	 * throughput totals are unaffected.
	 */
	probe->nss_present =
		file_exists("/sys/module/qca_nss_drv") ||
		file_exists("/sys/bus/platform/drivers/qca-nss") ||
		file_exists("/sys/kernel/debug/qca-nss-drv") ||
		file_exists("/proc/sys/dev/nss");

	probe->nss_bridge_mgr =
		file_exists("/sys/module/qca_nss_bridge_mgr");

	/* NSS-IFB (nss-ifb.ko) mirrors NSS physical-interface ingress into a
	 * virtual "nssifb" netdev so NSS-aware qdiscs (nsstbl / nssfq_codel)
	 * can shape ingress traffic in NSS core. Its presence means this
	 * router is using NSS for hardware QoS/SQM; nssifb's counters are
	 * mirrored ingress, not real client traffic — don't attach BPF to it,
	 * only observe it if the user wants. */
	probe->nss_ifb_active =
		file_exists("/sys/class/net/nssifb") ||
		file_exists("/sys/module/nss_ifb") ||
		file_exists("/sys/module/nss-ifb");

	/* NSS-PPE (Packet Processing Engine) is the newer hw accelerator on
	 * IPQ95xx / IPQ53xx platforms. Semantics match ECM: once PPE
	 * accelerates a flow, packets bypass the Linux stack. */
	probe->nss_ppe_active =
		file_exists("/sys/module/qca_nss_ppe") ||
		file_exists("/sys/module/ppe_drv") ||
		file_exists("/sys/kernel/debug/qca-nss-ppe") ||
		file_exists("/sys/kernel/debug/ppe_drv");

	/* NSS-NSM (Network Stats Manager): in-kernel per-flow stats
	 * aggregator. When present, it provides richer stats than bare
	 * conntrack sync. We only note its presence here — reading the
	 * aggregated stats needs genl/debugfs work that is out of scope. */
	probe->nss_nsm_active =
		file_exists("/sys/module/qca_nss_nsm") ||
		file_exists("/sys/module/nss_nsm") ||
		file_exists("/sys/kernel/debug/qca-nss-nsm");

	/* NSS data plane driver: owns the physical ports on NSS platforms.
	 * Used as a secondary signal for nss_present. */
	probe->nss_dp_active =
		file_exists("/sys/module/qca_nss_dp") ||
		file_exists("/sys/module/nss_dp");
	if (probe->nss_dp_active)
		probe->nss_present = true;

	/* qca-mcs: multicast snooping integration. Indicates multicast
	 * traffic is handled specially; does not change per-client
	 * accounting by itself. */
	probe->nss_mcs_active =
		file_exists("/sys/module/qca_mcs") ||
		file_exists("/sys/module/mc_snooping");

	probe->nss_ecm_active =
		file_exists("/sys/module/ecm") ||
		file_exists("/sys/kernel/debug/ecm");

	probe->nss_ecm_accelerated_connections = -1;
	probe->nss_ecm_tcp_connections = -1;
	probe->nss_ecm_udp_connections = -1;
	probe->nss_ecm_other_connections = -1;
	probe->nss_ecm_host_count = -1;
	probe->nss_ecm_mapping_count = -1;
	{
		FILE *fp = fopen("/sys/kernel/debug/ecm/ecm_db/connection_count", "r");
		if (fp) {
			int n = -1;
			if (fscanf(fp, "%d", &n) == 1 && n >= 0)
				probe->nss_ecm_accelerated_connections = n;
			fclose(fp);
		}
	}
	/* connection_count_simple is a text line:
	 *   "tcp 12 udp 34 other 5 total 51\n"
	 * Primarily for use by the luci-bwc service, per ECM source comment.
	 * Cheap to read, gives us protocol distribution of accelerated flows. */
	{
		FILE *fp = fopen("/sys/kernel/debug/ecm/ecm_db/connection_count_simple", "r");
		if (fp) {
			int tcp = -1, udp = -1, other = -1, total = -1;
			if (fscanf(fp, "tcp %d udp %d other %d total %d",
			           &tcp, &udp, &other, &total) == 4) {
				if (tcp   >= 0) probe->nss_ecm_tcp_connections   = tcp;
				if (udp   >= 0) probe->nss_ecm_udp_connections   = udp;
				if (other >= 0) probe->nss_ecm_other_connections = other;
				/* Prefer connection_count file above; use simple's
				 * total only if that failed. */
				if (probe->nss_ecm_accelerated_connections < 0 && total >= 0)
					probe->nss_ecm_accelerated_connections = total;
			}
			fclose(fp);
		}
	}
	/* ECM tracks L3 hosts and NAT mappings separately from flows.
	 * host_count ~= number of distinct LAN endpoints ECM has seen.
	 * mapping_count ~= NAT mappings (useful to cross-reference with
	 * our per-client row count). */
	{
		FILE *fp = fopen("/sys/kernel/debug/ecm/ecm_db/host_count", "r");
		if (fp) {
			int n = -1;
			if (fscanf(fp, "%d", &n) == 1 && n >= 0)
				probe->nss_ecm_host_count = n;
			fclose(fp);
		}
	}
	{
		FILE *fp = fopen("/sys/kernel/debug/ecm/ecm_db/mapping_count", "r");
		if (fp) {
			int n = -1;
			if (fscanf(fp, "%d", &n) == 1 && n >= 0)
				probe->nss_ecm_mapping_count = n;
			fclose(fp);
		}
	}

	/* Treat NSS+ECM (or PPE) as hardware flow offload: once acceleration
	 * is active the Linux-side BPF / nft flowtable sees nothing until a
	 * timeout or manual deceleration. */
	if (probe->nss_present && (probe->nss_ecm_active || probe->nss_ppe_active))
		probe->hardware_flow_offload = true;
}

static void inspect_service_presence(struct runtime_probe *probe)
{
	bool qosify_command = probe->qosify;

	inspect_package_uci(probe, "sqm", "sqm", &probe->sqm);
	inspect_package_uci(probe, "qosify", "qosify", &probe->qosify);
	inspect_package_uci(probe, "openclash", "openclash", &probe->openclash);
	inspect_package_uci(probe, "dae", "dae", &probe->dae);
	inspect_package_uci(probe, "daed", "daed", &probe->daed);
	inspect_package_uci(probe, "homeproxy", "homeproxy", &probe->homeproxy);
	inspect_package_uci(probe, "nlbwmon", "nlbwmon", &probe->nlbwmon);
	probe->qosify = probe->qosify || qosify_command;
	probe->dae = probe->dae || probe->daed || file_exists("/etc/config/dae") || file_exists("/etc/config/daed");
	probe->openclash = probe->openclash || file_exists("/etc/config/openclash");
	probe->homeproxy = probe->homeproxy || file_exists("/etc/config/homeproxy");
	probe->nlbwmon = probe->nlbwmon || file_exists("/etc/config/nlbwmon");
	if (probe->openclash) {
		inspect_openclash_uci_options(probe);
		inspect_dnsmasq_openclash_chain(probe);
	}

	if (probe->sqm)
		add_warning(probe, "sqm_detected");
	if (probe->qosify)
		add_warning(probe, "qosify_detected");
	if (probe->openclash)
		add_warning(probe, "openclash_detected");
	if (probe->openclash_fake_ip)
		add_warning(probe, "openclash_fake_ip_low_remote_confidence");
	if (probe->openclash_tun_mix)
		add_warning(probe, "openclash_tun_conntrack_low_confidence");
	if (probe->openclash_dns_chain_incomplete)
		add_warning(probe, "openclash_dns_chain_incomplete");
	if (probe->openclash_router_self_proxy)
		add_warning(probe, "openclash_router_self_proxy_detected");
	if (probe->dae)
		add_warning(probe, "dae_detected");
	if (probe->homeproxy)
		add_warning(probe, "homeproxy_detected");
	if (probe->nlbwmon)
		add_warning(probe, "nlbwmon_counter_conflict");
}

static void add_conflicts_from_probe(struct runtime_probe *probe)
{
	if (probe->hardware_flow_offload)
		add_conflict(probe, "hardware_flow_offload", "warning",
			     "Hardware flow offload hides traffic from CPU-visible collectors.");
	if (probe->software_flow_offload)
		add_conflict(probe, "software_flow_offload", "info",
			     "Software flow offload may reduce counter confidence for some flows.");
	if (probe->fullcone)
		add_conflict(probe, "fullcone", "info",
			     "Fullcone NAT is present and should be considered when interpreting flow ownership.");
	if (probe->sqm || probe->qosify || probe->ifb)
		add_conflict(probe, "existing_qos", "warning",
			     "Existing QoS/IFB components may already own tc hooks.");
	if (probe->openclash || probe->dae || probe->homeproxy)
		add_conflict(probe, "proxy_stack", "info",
			     "Local proxy stacks can alter LAN/WAN flow paths.");
	if (probe->nlbwmon)
		add_conflict(probe, "nlbwmon_counter_conflict", "warning",
			     "nlbwmon may use zero-on-read counters; lanspeedd does not read or disturb nlbwmon counters.");
}

static bool bpf_full_available(const struct runtime_probe *probe)
{
	return bpf_runtime_metrics_available(probe);
}

static bool conntrack_fallback_accounting_safe(const struct runtime_probe *probe)
{
	return probe->nf_conntrack_acct;
}

static bool conntrack_fallback_active(const struct runtime_probe *probe)
{
	return enable_conntrack_fallback && !bpf_full_available(probe) &&
	       conntrack_fallback_accounting_safe(probe);
}

static bool conntrack_fallback_low_confidence(const struct runtime_probe *probe)
{
	/* NSS ECM / PPE syncs per-flow byte counters (incl. hw-offloaded
	 * routed and bridged flows) back into conntrack at ~1-2 s cadence.
	 * In that scenario hardware_flow_offload=true is not a confidence
	 * killer because conntrack_acct data is still accurate, just
	 * secondly. */
	bool nss_ecm_sync = probe->nss_present && (probe->nss_ecm_active || probe->nss_ppe_active);
	bool hw_off_non_nss = probe->hardware_flow_offload && !nss_ecm_sync;

	return conntrack_fallback_active(probe) &&
	       (!probe->flowtable_counter || probe->software_flow_offload ||
		hw_off_non_nss || probe->openclash_fake_ip ||
		probe->openclash_tun_mix || probe->openclash_router_self_proxy ||
		probe->openclash_udp_proxy || probe->dae || probe->homeproxy ||
		probe->sqm || probe->qosify || probe->ifb ||
		probe->nlbwmon || probe->probe_error || probe->lan_probe_error);
}

static const char *conntrack_fallback_confidence(const struct runtime_probe *probe)
{
	if (!conntrack_fallback_active(probe))
		return "unsupported";
	if (conntrack_fallback_low_confidence(probe))
		return "low";
	return "medium";
}

static void add_conntrack_fallback_runtime_warnings(struct runtime_probe *probe)
{
	if (!conntrack_fallback_active(probe))
		return;

	/* With NSS ECM / PPE active, the counter sync covers bridged flows
	 * too, so the "routed / NAT only" disclaimer does not apply. */
	if (!(probe->nss_present && (probe->nss_ecm_active || probe->nss_ppe_active)))
		add_warning(probe, "conntrack_routed_nat_only");

	if (!probe->flowtable_counter)
		add_warning(probe, "flowtable_counter_missing");
	if (probe->nlbwmon)
		add_warning(probe, "nlbwmon_counter_conflict");
}

static void add_collector_evidence(struct runtime_probe *probe)
{
	struct json_object *collector = json_object_new_object();
	struct json_object *attach_model = json_object_new_object();
	struct json_object *attach_edges = json_object_new_array();
	struct json_object *excluded_edges = json_object_new_array();
	struct json_object *tc_filter = json_object_new_object();
	struct json_object *map_model = json_object_new_object();
	struct json_object *rate_model = json_object_new_object();
	struct json_object *dedupe_model = json_object_new_object();
	struct json_object *router_local_model = json_object_new_object();
	struct json_object *topology_identity_model = json_object_new_object();
	struct json_object *uplink_encapsulation_model = json_object_new_object();
	struct json_object *uplink_wan_side = json_object_new_array();
	struct json_object *map_key = json_object_new_array();
	struct json_object *map_counters = json_object_new_array();
	struct json_object *directions = json_object_new_object();
	struct json_object *anomaly_warnings = json_object_new_array();
	struct json_object *warnings = json_object_new_array();
	struct json_object *conntrack = json_object_new_object();
	struct json_object *conntrack_active_when = json_object_new_array();
	struct json_object *conntrack_inactive_when = json_object_new_array();
	struct json_object *conntrack_warnings = json_object_new_array();
	struct json_object *conntrack_sources = json_object_new_array();
	struct json_object *conntrack_forbidden = json_object_new_array();
	struct json_object *conntrack_identity = json_object_new_object();
	struct json_object *conntrack_directions = json_object_new_object();
	struct json_object *router_self = json_object_new_object();

	json_object_object_add(collector, "source", json_object_new_string("lanspeedd_tc_bpf_collector"));
	json_object_object_add(collector, "runtime_safe", json_object_new_boolean(true));
	json_object_object_add(collector, "enabled", json_object_new_boolean(enable_bpf));
	json_object_object_add(collector, "bpf_source", json_object_new_string(LANSPEED_BPF_SOURCE));
	json_object_object_add(collector, "runtime_object", json_object_new_string(LANSPEED_BPF_OBJECT_PATH));
	json_object_object_add(collector, "optional_package_present", json_object_new_boolean(probe->bpf_package));
	json_object_object_add(collector, "bpf_object_present", json_object_new_boolean(probe->bpf_object));
	json_object_object_add(collector, "safe_attach", json_object_new_boolean(probe->safe_attach));
	json_object_object_add(collector, "bpf_assets_are_evidence_only", json_object_new_boolean(true));
	json_object_object_add(collector, "runtime_attach_map_read_success", json_object_new_boolean(probe->bpf_runtime_metrics));
	json_object_object_add(collector, "live_metrics", json_object_new_boolean(probe->bpf_runtime_metrics));
	json_object_object_add(collector, "runtime_gate_warning", json_object_new_string("bpf_runtime_loader_unavailable"));
	json_object_object_add(collector, "map_full", json_object_new_boolean(probe->map_full));

	json_object_array_add(attach_edges, json_object_new_string("lan_bridge_members"));
	json_object_array_add(attach_edges, json_object_new_string("vlan_subinterfaces"));
	json_object_array_add(attach_edges, json_object_new_string("wlan_interfaces"));
	json_object_array_add(excluded_edges, json_object_new_string("wan"));
	json_object_array_add(excluded_edges, json_object_new_string("tun"));
	json_object_array_add(excluded_edges, json_object_new_string("ppp"));
	json_object_array_add(excluded_edges, json_object_new_string("wg"));
	json_object_array_add(excluded_edges, json_object_new_string("dae0"));
	json_object_array_add(excluded_edges, json_object_new_string("dae0peer"));
	json_object_object_add(attach_model, "cpu_visible_lan_edges_only", json_object_new_boolean(true));
	json_object_object_add(attach_model, "detected_lan_edge", json_object_new_boolean(probe->lan_edge));
	json_object_object_add(attach_model, "allowed", attach_edges);
	json_object_object_add(attach_model, "excluded", excluded_edges);

	json_object_object_add(tc_filter, "qdisc", json_object_new_string("clsact"));
	json_object_object_add(tc_filter, "coexistence", json_object_new_string("create_or_reuse_clsact_and_append_owned_filter_only"));
	json_object_object_add(tc_filter, "delete_existing", json_object_new_boolean(false));
	json_object_object_add(tc_filter, "reorder_existing", json_object_new_boolean(false));
	json_object_object_add(tc_filter, "owner", json_object_new_string(LANSPEED_TC_FILTER_OWNER));
	json_object_object_add(tc_filter, "pref", json_object_new_int(LANSPEED_TC_FILTER_PREF));
	json_object_object_add(tc_filter, "handle", json_object_new_string(LANSPEED_TC_FILTER_HANDLE));
	json_object_object_add(tc_filter, "existing_filters_detected", json_object_new_boolean(probe->existing_tc_filters));
	json_object_object_add(tc_filter, "existing_filters", json_object_get(probe->tc_filters));
	json_object_object_add(tc_filter, "conflict", json_object_new_boolean(probe->tc_filter_conflict));
	json_object_object_add(tc_filter, "conflict_warning", json_object_new_string("tc_filter_conflict"));

	json_object_array_add(map_key, json_object_new_string("ifindex"));
	json_object_array_add(map_key, json_object_new_string("vlan_or_zone"));
	json_object_array_add(map_key, json_object_new_string("mac"));
	json_object_array_add(map_key, json_object_new_string("direction"));
	json_object_array_add(map_counters, json_object_new_string("bytes"));
	json_object_array_add(map_counters, json_object_new_string("packets"));
	json_object_array_add(map_counters, json_object_new_string("last_seen"));
	json_object_object_add(directions, "tx_bps", json_object_new_string("client-originated traffic from the client point of view"));
	json_object_object_add(directions, "rx_bps", json_object_new_string("traffic to client from the client point of view"));
	json_object_object_add(map_model, "key", map_key);
	json_object_object_add(map_model, "counters", map_counters);
	json_object_object_add(map_model, "default_max_clients", json_object_new_int(DEFAULT_MAX_CLIENTS));
	json_object_object_add(map_model, "configured_max_clients", json_object_new_int(max_clients));
	json_object_object_add(map_model, "full_warning", json_object_new_string("map_full"));
	json_object_object_add(map_model, "client_limit_warning", json_object_new_string("client_limit_exceeded"));
	json_object_object_add(map_model, "map_read_failure_warning", json_object_new_string("map_read_failed"));
	json_object_object_add(map_model, "directions", directions);

	json_object_array_add(anomaly_warnings, json_object_new_string("counter_anomaly"));
	json_object_array_add(anomaly_warnings, json_object_new_string("time_rollback"));
	json_object_object_add(rate_model, "default_refresh_interval_ms", json_object_new_int(DEFAULT_REFRESH_INTERVAL_MS));
	json_object_object_add(rate_model, "minimum_refresh_interval_ms", json_object_new_int(MIN_REFRESH_INTERVAL_MS));
	json_object_object_add(rate_model, "configured_refresh_interval_ms", json_object_new_int(refresh_interval_ms));
	json_object_object_add(rate_model, "refresh_interval_warning", json_object_new_string("refresh_interval_below_minimum"));
	json_object_object_add(rate_model, "window_count", json_object_new_int(RATE_WINDOW_COUNT));
	json_object_object_add(rate_model, "stale_client_ms", json_object_new_int(STALE_CLIENT_MS));
	json_object_object_add(rate_model, "delta_formula", json_object_new_string("max(0, current_bytes - previous_bytes) * 8 * 1000 / delta_ms"));
	json_object_object_add(rate_model, "negative_rate_policy", json_object_new_string("clamp_to_zero_per_client"));
	json_object_object_add(rate_model, "counter_wrap_policy", json_object_new_string("counter_anomaly_and_zero_delta"));
	json_object_object_add(rate_model, "time_rollback_policy", json_object_new_string("time_rollback_and_zero_delta"));
	json_object_object_add(rate_model, "anomaly_warnings", anomaly_warnings);

	json_object_object_add(dedupe_model, "lan_to_lan", json_object_new_string("merge matching frame observations before aggregate totals"));
	json_object_object_add(dedupe_model, "visibility_unknown_mode", json_object_new_string("Degraded"));
	json_object_object_add(dedupe_model, "visibility_unknown_warning", json_object_new_string("lan_to_lan_visibility_unknown"));
	json_object_object_add(dedupe_model, "visibility_limited_mode", json_object_new_string("Degraded"));
	json_object_object_add(dedupe_model, "visibility_limited_warning", json_object_new_string("lan_to_lan_visibility_limited"));
	json_object_object_add(dedupe_model, "cpu_visible_only", json_object_new_boolean(true));
	json_object_object_add(dedupe_model, "complete_coverage_claimed_for_hardware_switch_paths", json_object_new_boolean(false));
	json_object_object_add(dedupe_model, "duplicate_policy", json_object_new_string("do_not_count_one_lan_to_lan_frame_twice"));

	json_object_object_add(router_local_model, "client_perspective", json_object_new_boolean(true));
	json_object_object_add(router_local_model, "client_to_router", json_object_new_string("tx_bps"));
	json_object_object_add(router_local_model, "router_to_client", json_object_new_string("rx_bps"));
	json_object_object_add(router_local_model, "router_originated_bucket", json_object_new_string("router_self"));
	json_object_object_add(router_local_model, "router_originated_alias", json_object_new_string("local_router"));
	json_object_object_add(router_local_model, "client_attribution", json_object_new_string("never_attribute_router_originated_traffic_to_lan_client"));

	json_object_object_add(topology_identity_model, "primary_key", json_object_new_string("mac+zone"));
	json_object_object_add(topology_identity_model, "preserve_mac_zone_identity", json_object_new_boolean(true));
	json_object_object_add(topology_identity_model, "guest_vlan", json_object_new_string("separate zone identity"));
	json_object_object_add(topology_identity_model, "multi_bridge", json_object_new_string("bridge zone participates in identity key"));
	json_object_object_add(topology_identity_model, "wifi_wds_ap_isolation", json_object_new_string("wireless attachment metadata must not collapse MAC+zone identity"));
	json_object_object_add(topology_identity_model, "duplicate_mac_warning", json_object_new_string("duplicate_mac_across_vlans"));

	json_object_array_add(uplink_wan_side, json_object_new_string("pppoe"));
	json_object_array_add(uplink_wan_side, json_object_new_string("wg"));
	json_object_array_add(uplink_wan_side, json_object_new_string("tun"));
	json_object_object_add(uplink_encapsulation_model, "wan_side_only", uplink_wan_side);
	json_object_object_add(uplink_encapsulation_model, "identity_policy", json_object_new_string("PPPoE/WG/TUN evidence never changes LAN-edge client MAC ownership"));

	if (!enable_bpf)
		json_object_array_add(warnings, json_object_new_string("bpf_disabled"));
	if (!probe->bpf_package)
		json_object_array_add(warnings, json_object_new_string("bpf_optional_package_missing"));
	if (!probe->bpf_object)
		json_object_array_add(warnings, json_object_new_string("bpf_object_missing"));
	if (!probe->lan_edge)
		json_object_array_add(warnings, json_object_new_string("lan_edge_missing"));
	if (probe->map_full)
		json_object_array_add(warnings, json_object_new_string("map_full"));
	if (refresh_interval_clamped)
		json_object_array_add(warnings, json_object_new_string("refresh_interval_below_minimum"));
	if (probe->tc_filter_conflict)
		json_object_array_add(warnings, json_object_new_string("tc_filter_conflict"));
	if (enable_bpf && !probe->safe_attach)
		json_object_array_add(warnings, json_object_new_string("unsafe_attach"));
	if (enable_bpf && probe->safe_attach && !probe->bpf_runtime_metrics) {
		json_object_array_add(warnings, json_object_new_string("bpf_runtime_loader_unavailable"));
		json_object_array_add(warnings, json_object_new_string("live_metrics_unavailable"));
	}

	json_object_array_add(conntrack_active_when, json_object_new_string("bpf_full_unavailable"));
	json_object_array_add(conntrack_active_when, json_object_new_string("enable_conntrack_fallback=1"));
	json_object_array_add(conntrack_active_when, json_object_new_string("nf_conntrack_acct=1"));
	json_object_array_add(conntrack_inactive_when, json_object_new_string("bpf_full_available"));
	json_object_array_add(conntrack_inactive_when, json_object_new_string("enable_conntrack_fallback=0"));
	json_object_array_add(conntrack_inactive_when, json_object_new_string("conntrack_acct_disabled"));
	json_object_array_add(conntrack_sources, json_object_new_string("procfs_conntrack_acct_orig_reply_bytes"));
	json_object_array_add(conntrack_forbidden, json_object_new_string("firewall_forward_chain_counters"));
	json_object_array_add(conntrack_forbidden, json_object_new_string("iptables_forward_chain_counters"));
	json_object_array_add(conntrack_forbidden, json_object_new_string("nft_forward_chain_counters"));
	json_object_array_add(conntrack_forbidden, json_object_new_string("nlbwmon_counters"));
	json_object_array_add(conntrack_warnings, json_object_new_string("conntrack_routed_nat_only"));
	if (!probe->nf_conntrack_acct)
		json_object_array_add(conntrack_warnings, json_object_new_string("conntrack_acct_disabled"));
	if (!probe->flowtable_counter)
		json_object_array_add(conntrack_warnings, json_object_new_string("flowtable_counter_missing"));
	if (probe->nlbwmon)
		json_object_array_add(conntrack_warnings, json_object_new_string("nlbwmon_counter_conflict"));
	if (probe->openclash || probe->dae || probe->homeproxy)
		json_object_array_add(conntrack_warnings, json_object_new_string("proxy_path_confidence_low"));
	if (probe->openclash_fake_ip)
		json_object_array_add(conntrack_warnings, json_object_new_string("openclash_fake_ip_low_remote_confidence"));
	if (probe->openclash_tun_mix)
		json_object_array_add(conntrack_warnings, json_object_new_string("openclash_tun_conntrack_low_confidence"));
	if (probe->openclash_dns_chain_incomplete)
		json_object_array_add(conntrack_warnings, json_object_new_string("openclash_dns_chain_incomplete"));
	if (probe->sqm || probe->qosify || probe->ifb)
		json_object_array_add(conntrack_warnings, json_object_new_string("qos_ifb_confidence_low"));
	if (probe->hardware_flow_offload || probe->software_flow_offload)
		json_object_array_add(conntrack_warnings, json_object_new_string("flow_offload_confidence_low"));

	json_object_object_add(conntrack_directions, "tx_bps", json_object_new_string("LAN client original-direction bytes from conntrack accounting"));
	json_object_object_add(conntrack_directions, "rx_bps", json_object_new_string("LAN client reply-direction bytes from conntrack accounting"));
	json_object_object_add(conntrack_identity, "primary_key", json_object_new_string("mac+zone"));
	json_object_object_add(conntrack_identity, "ip_role", json_object_new_string("LAN client IP maps to an existing MAC/zone identity and is never the primary identity"));
	json_object_object_add(conntrack_identity, "router_self_policy", json_object_new_string("router-originated proxy traffic is bucketed as router_self and is never attributed to a LAN client"));
	json_object_object_add(conntrack_identity, "excluded_interfaces", json_object_new_string("dae0,dae0peer,tun*,ppp*,wg* are never LAN client MAC/IP sources"));

	json_object_object_add(conntrack, "source", json_object_new_string("lanspeedd_procfs_conntrack_acct"));
	json_object_object_add(conntrack, "enabled", json_object_new_boolean(enable_conntrack_fallback));
	json_object_object_add(conntrack, "active", json_object_new_boolean(conntrack_fallback_active(probe)));
	json_object_object_add(conntrack, "collector_mode", json_object_new_string("conntrack"));
	json_object_object_add(conntrack, "mode", json_object_new_string("Degraded"));
	json_object_object_add(conntrack, "confidence", json_object_new_string(conntrack_fallback_confidence(probe)));
	json_object_object_add(conntrack, "bpf_full_blocked_by_runtime_gate", json_object_new_boolean(!probe->bpf_runtime_metrics));
	json_object_object_add(conntrack, "coverage", json_object_new_string("routed_nat_only"));
	json_object_object_add(conntrack, "coverage_warning", json_object_new_string("conntrack_routed_nat_only"));
	json_object_object_add(conntrack, "active_when", conntrack_active_when);
	json_object_object_add(conntrack, "inactive_when", conntrack_inactive_when);
	json_object_object_add(conntrack, "counter_sources", conntrack_sources);
	json_object_object_add(conntrack, "forbidden_sources", conntrack_forbidden);
	json_object_object_add(conntrack, "identity_model", conntrack_identity);
	json_object_object_add(conntrack, "directions", conntrack_directions);
	json_object_object_add(conntrack, "nf_conntrack_acct", json_object_new_boolean(probe->nf_conntrack_acct));
	json_object_object_add(conntrack, "flowtable_counter", json_object_new_boolean(probe->flowtable_counter));
	json_object_object_add(conntrack, "nlbwmon_read_counters", json_object_new_boolean(false));
	json_object_object_add(conntrack, "warnings", conntrack_warnings);

	json_object_object_add(router_self, "bucket", json_object_new_string("router_self"));
	json_object_object_add(router_self, "alias", json_object_new_string("local_router"));
	json_object_object_add(router_self, "enabled", json_object_new_boolean(probe->openclash_router_self_proxy));
	json_object_object_add(router_self, "client_attribution", json_object_new_string("never_attribute_to_lan_client"));
	json_object_object_add(router_self, "identity_key", json_object_new_string("router_self@local_router"));
	json_object_object_add(router_self, "warning", json_object_new_string("openclash_router_self_proxy_detected"));

	json_object_object_add(collector, "attach_model", attach_model);
	json_object_object_add(collector, "tc_filter", tc_filter);
	json_object_object_add(collector, "map_model", map_model);
	json_object_object_add(collector, "rate_model", rate_model);
	json_object_object_add(collector, "dedupe_model", dedupe_model);
	json_object_object_add(collector, "router_local_model", router_local_model);
	json_object_object_add(collector, "topology_identity_model", topology_identity_model);
	json_object_object_add(collector, "uplink_encapsulation_model", uplink_encapsulation_model);
	json_object_object_add(collector, "conntrack_fallback_model", conntrack);
	json_object_object_add(collector, "router_self_model", router_self);
	json_object_object_add(collector, "warnings", warnings);
	json_object_object_add(probe->evidence, "collector", collector);
}

static void inspect_runtime(struct runtime_probe *probe)
{
	inspect_command_capabilities(probe);
	inspect_firewall_uci(probe);
	inspect_tc(probe);
	inspect_files(probe);
	inspect_bpf_assets(probe);
	inspect_ubus(probe);
	inspect_dae_runtime(probe);
	inspect_nss(probe);
	inspect_collector_attach_model(probe);
	inspect_service_presence(probe);

	if (probe->software_flow_offload)
		add_warning(probe, "software_flow_offload_enabled");
	if (probe->hardware_flow_offload)
		add_warning(probe, "hardware_flow_offload_unsupported");
	if (probe->nss_present)
		add_warning(probe, "nss_detected");
	if (probe->nss_ecm_active)
		add_warning(probe, "nss_ecm_offload_active");
	if (probe->nss_ppe_active)
		add_warning(probe, "nss_ppe_offload_active");
	if (probe->nss_ifb_active)
		add_warning(probe, "nss_ifb_detected");
	if (rejected_nssifb_collect)
		add_warning(probe, "nssifb_collect_rejected");
	if (probe->fullcone) {
		add_warning(probe, "fullcone_detected");
		add_warning(probe, "fullcone_nat_enabled");
	}
	if (refresh_interval_clamped)
		add_warning(probe, "refresh_interval_below_minimum");
	add_conntrack_fallback_runtime_warnings(probe);
	add_conflicts_from_probe(probe);
}

static void init_runtime_probe(struct runtime_probe *probe)
{
	memset(probe, 0, sizeof(*probe));
	probe->warnings = json_object_new_array();
	probe->conflicts = json_object_new_array();
	probe->evidence = json_object_new_object();
	probe->tc_filters = json_object_new_array();
	probe->commands = json_object_new_object();
	probe->files = json_object_new_object();
	probe->uci = json_object_new_object();
	probe->ubus_evidence = json_object_new_object();
	probe->source_commands = json_object_new_array();
	probe->source_files = json_object_new_array();
	probe->source_uci = json_object_new_array();
	probe->source_ubus = json_object_new_array();
}

static void free_runtime_probe(struct runtime_probe *probe)
{
	json_object_put(probe->warnings);
	json_object_put(probe->conflicts);
	json_object_put(probe->evidence);
	json_object_put(probe->tc_filters);
	json_object_put(probe->commands);
	json_object_put(probe->files);
	json_object_put(probe->uci);
	json_object_put(probe->ubus_evidence);
	json_object_put(probe->source_commands);
	json_object_put(probe->source_files);
	json_object_put(probe->source_uci);
	json_object_put(probe->source_ubus);
}

static const char *probe_mode(const struct runtime_probe *probe)
{
	if (!probe->tc && !conntrack_fallback_active(probe))
		return "Unsupported";
	if (!bpf_full_available(probe))
		return "Degraded";
	return "Full";
}

static const char *probe_confidence(const struct runtime_probe *probe, const char *mode)
{
	if (!strcmp(mode, "Full"))
		return "high";
	if (probe->probe_error || probe->lan_probe_error)
		return "low";
	if (!strcmp(mode, "Unsupported"))
		return "unsupported";
	if (conntrack_fallback_low_confidence(probe))
		return "low";
	return "medium";
}

static void finish_probe_evidence(struct runtime_probe *probe, const char *method)
{
	struct json_object *sources = json_object_new_object();
	struct json_object *openclash = json_object_new_object();
	struct json_object *dae = json_object_new_object();

	add_collector_evidence(probe);
	json_object_object_add(probe->evidence, "software_flow_offload",
			       json_object_new_string(enabled_state(probe->software_flow_offload)));
	json_object_object_add(probe->evidence, "hardware_flow_offload",
			       json_object_new_string(enabled_state(probe->hardware_flow_offload)));
	{
		struct json_object *nss = json_object_new_object();
		struct json_object *subs = json_object_new_array();

		json_object_object_add(nss, "present", json_object_new_boolean(probe->nss_present));
		json_object_object_add(nss, "ecm_offload_active", json_object_new_boolean(probe->nss_ecm_active));
		json_object_object_add(nss, "ppe_offload_active", json_object_new_boolean(probe->nss_ppe_active));
		json_object_object_add(nss, "bridge_mgr", json_object_new_boolean(probe->nss_bridge_mgr));
		json_object_object_add(nss, "ifb_active", json_object_new_boolean(probe->nss_ifb_active));
		json_object_object_add(nss, "nsm_active", json_object_new_boolean(probe->nss_nsm_active));
		json_object_object_add(nss, "dp_active", json_object_new_boolean(probe->nss_dp_active));
		json_object_object_add(nss, "mcs_active", json_object_new_boolean(probe->nss_mcs_active));
		if (probe->nss_ecm_accelerated_connections >= 0)
			json_object_object_add(nss, "accelerated_connections",
			                       json_object_new_int(probe->nss_ecm_accelerated_connections));
		if (probe->nss_ecm_tcp_connections >= 0)
			json_object_object_add(nss, "accelerated_tcp",
			                       json_object_new_int(probe->nss_ecm_tcp_connections));
		if (probe->nss_ecm_udp_connections >= 0)
			json_object_object_add(nss, "accelerated_udp",
			                       json_object_new_int(probe->nss_ecm_udp_connections));
		if (probe->nss_ecm_other_connections >= 0)
			json_object_object_add(nss, "accelerated_other",
			                       json_object_new_int(probe->nss_ecm_other_connections));
		if (probe->nss_ecm_host_count >= 0)
			json_object_object_add(nss, "host_count",
			                       json_object_new_int(probe->nss_ecm_host_count));
		if (probe->nss_ecm_mapping_count >= 0)
			json_object_object_add(nss, "mapping_count",
			                       json_object_new_int(probe->nss_ecm_mapping_count));

		if (probe->nss_present)     json_object_array_add(subs, json_object_new_string("drv"));
		if (probe->nss_dp_active)   json_object_array_add(subs, json_object_new_string("dp"));
		if (probe->nss_ecm_active)  json_object_array_add(subs, json_object_new_string("ecm"));
		if (probe->nss_ppe_active)  json_object_array_add(subs, json_object_new_string("ppe"));
		if (probe->nss_nsm_active)  json_object_array_add(subs, json_object_new_string("nsm"));
		if (probe->nss_bridge_mgr)  json_object_array_add(subs, json_object_new_string("bridge_mgr"));
		if (probe->nss_ifb_active)  json_object_array_add(subs, json_object_new_string("ifb"));
		if (probe->nss_mcs_active)  json_object_array_add(subs, json_object_new_string("mcs"));
		json_object_object_add(nss, "subsystems", subs);

		json_object_object_add(nss, "counter_source", json_object_new_string(
			probe->nss_ppe_active ? "ppe_conntrack_sync"
			: probe->nss_ecm_active ? "ecm_conntrack_sync"
			: "netdev_counters_only"));
		json_object_object_add(nss, "counter_cadence_seconds", json_object_new_int(
			(probe->nss_ecm_active || probe->nss_ppe_active) ? 2 : 0));
		json_object_object_add(nss, "bpf_visibility", json_object_new_string(
			(probe->nss_ecm_active || probe->nss_ppe_active)
				? "slow_path_only_until_deceleration"
				: "full_when_nss_not_offloading"));
		json_object_object_add(nss, "interface_counters_accurate",
		                       json_object_new_boolean(true));
		json_object_object_add(nss, "nssifb_policy", json_object_new_string(
			probe->nss_ifb_active
				? "mirror_of_physical_ingress_not_a_real_client_source"
				: "not_present"));
		json_object_object_add(probe->evidence, "nss", nss);
	}
	json_object_object_add(probe->evidence, "fullcone",
			       json_object_new_string(enabled_state(probe->fullcone)));
	json_object_object_add(probe->evidence, "fullcone_nat_enabled",
			       json_object_new_boolean(probe->fullcone));
	json_object_object_add(probe->evidence, "flowtable_counter",
			       json_object_new_string(present_state(probe->flowtable_counter)));

	json_object_object_add(openclash, "installed", json_object_new_boolean(probe->openclash));
	json_object_object_add(openclash, "en_mode", json_object_new_string(probe->openclash_en_mode[0] ? probe->openclash_en_mode : "unknown"));
	json_object_object_add(openclash, "fake_ip", json_object_new_boolean(probe->openclash_fake_ip));
	json_object_object_add(openclash, "tun_mix", json_object_new_boolean(probe->openclash_tun_mix));
	json_object_object_add(openclash, "enable_redirect_dns", json_object_new_boolean(probe->openclash_redirect_dns));
	json_object_object_add(openclash, "dnsmasq_to_127_0_0_1_7874", json_object_new_boolean(probe->openclash_dnsmasq_chain));
	json_object_object_add(openclash, "dns_chain_complete", json_object_new_boolean(!probe->openclash_redirect_dns || probe->openclash_dnsmasq_chain));
	json_object_object_add(openclash, "router_self_proxy", json_object_new_boolean(probe->openclash_router_self_proxy));
	json_object_object_add(openclash, "enable_udp_proxy", json_object_new_boolean(probe->openclash_udp_proxy));
	json_object_object_add(openclash, "stack_type", json_object_new_string(probe->openclash_stack_type[0] ? probe->openclash_stack_type : "unknown"));
	json_object_object_add(openclash, "ipv6_enable", json_object_new_boolean(probe->openclash_ipv6));
	json_object_object_add(openclash, "remote_identity_policy", json_object_new_string("fake-ip and proxy remote addresses are metadata only, never LAN client identity"));
	json_object_object_add(openclash, "primary_bpf_policy", json_object_new_string("do_not_disable_lan_edge_bpf_when_openclash_is_present"));
	json_object_object_add(openclash, "router_self_bucket", json_object_new_string("router_self"));
	json_object_object_add(probe->evidence, "openclash", openclash);

	json_object_object_add(dae, "installed", json_object_new_boolean(probe->dae));
	json_object_object_add(dae, "dae_config", json_object_new_boolean(probe->dae_config));
	json_object_object_add(dae, "daed_config", json_object_new_boolean(probe->daed_config));
	json_object_object_add(dae, "dae_service", json_object_new_boolean(probe->dae_service));
	json_object_object_add(dae, "daed_service", json_object_new_boolean(probe->daed_service));
	json_object_object_add(dae, "dae0", json_object_new_boolean(probe->dae_iface));
	json_object_object_add(dae, "dae0peer", json_object_new_boolean(probe->dae_peer_iface));
	json_object_object_add(dae, "tc_filters", json_object_get(probe->tc_filters));
	json_object_object_add(dae, "fwmark", json_object_new_string(DAE_FWMARK));
	json_object_object_add(dae, "fwmark_detected", json_object_new_boolean(probe->dae_fwmark));
	json_object_object_add(dae, "route_table", json_object_new_string(DAE_ROUTE_TABLE));
	json_object_object_add(dae, "route_table_detected", json_object_new_boolean(probe->dae_route_table));
	json_object_object_add(dae, "dns_udp53_detected", json_object_new_boolean(probe->dae_dns_udp53));
	json_object_object_add(dae, "uplink_evidence_policy", json_object_new_string("TUN/PPP/WG/dae interfaces are proxy/uplink evidence only, never LAN client identity sources"));
	json_object_object_add(dae, "identity_policy", json_object_new_string("dae0 and dae0peer MAC/IP observations are excluded from LAN clients"));
	json_object_object_add(probe->evidence, "dae", dae);

	json_object_object_add(sources, "command", probe->source_commands);
	json_object_object_add(sources, "file", probe->source_files);
	json_object_object_add(sources, "uci", probe->source_uci);
	json_object_object_add(sources, "ubus", probe->source_ubus);

	json_object_object_add(probe->evidence, "source", json_object_new_string("lanspeedd_runtime_probe"));
	json_object_object_add(probe->evidence, "method", json_object_new_string(method));
	json_object_object_add(probe->evidence, "read_only", json_object_new_boolean(true));
	json_object_object_add(probe->evidence, "probe_sources", sources);
	json_object_object_add(probe->evidence, "commands", probe->commands);
	json_object_object_add(probe->evidence, "files", probe->files);
	json_object_object_add(probe->evidence, "uci", probe->uci);
	json_object_object_add(probe->evidence, "ubus", probe->ubus_evidence);
	json_object_object_add(probe->evidence, "probe_error", json_object_new_boolean(probe->probe_error || probe->lan_probe_error));
	json_object_object_add(probe->evidence, "lan_probe_error", json_object_new_boolean(probe->lan_probe_error));
}

static void add_capabilities_from_values(struct json_object *parent, bool bpf,
					 bool conntrack_fallback, bool live_metrics,
					 const struct runtime_probe *probe)
{
	struct json_object *capabilities = json_object_new_object();

	json_object_object_add(capabilities, "bpf", json_object_new_boolean(bpf));
	json_object_object_add(capabilities, "bpf_package", json_object_new_boolean(probe ? probe->bpf_package : false));
	json_object_object_add(capabilities, "bpf_object", json_object_new_boolean(probe ? probe->bpf_object : false));
	json_object_object_add(capabilities, "bpf_runtime_metrics", json_object_new_boolean(probe ? probe->bpf_runtime_metrics : false));
	json_object_object_add(capabilities, "conntrack_fallback", json_object_new_boolean(probe ? conntrack_fallback_active(probe) : conntrack_fallback));
	json_object_object_add(capabilities, "live_metrics", json_object_new_boolean(live_metrics));
	json_object_object_add(capabilities, "fw4", json_object_new_boolean(probe ? probe->fw4 : false));
	json_object_object_add(capabilities, "nft", json_object_new_boolean(probe ? probe->nft : false));
	json_object_object_add(capabilities, "software_flow_offload", json_object_new_boolean(probe ? probe->software_flow_offload : false));
	json_object_object_add(capabilities, "hardware_flow_offload", json_object_new_boolean(probe ? probe->hardware_flow_offload : false));
	json_object_object_add(capabilities, "nss", json_object_new_boolean(probe ? probe->nss_present : false));
	json_object_object_add(capabilities, "nss_ecm_offload", json_object_new_boolean(probe ? probe->nss_ecm_active : false));
	json_object_object_add(capabilities, "nss_ppe_offload", json_object_new_boolean(probe ? probe->nss_ppe_active : false));
	json_object_object_add(capabilities, "nss_bridge_mgr", json_object_new_boolean(probe ? probe->nss_bridge_mgr : false));
	json_object_object_add(capabilities, "nss_ifb", json_object_new_boolean(probe ? probe->nss_ifb_active : false));
	json_object_object_add(capabilities, "nss_nsm", json_object_new_boolean(probe ? probe->nss_nsm_active : false));
	json_object_object_add(capabilities, "nss_dp", json_object_new_boolean(probe ? probe->nss_dp_active : false));
	json_object_object_add(capabilities, "nss_mcs", json_object_new_boolean(probe ? probe->nss_mcs_active : false));
	json_object_object_add(capabilities, "fullcone", json_object_new_boolean(probe ? probe->fullcone : false));
	json_object_object_add(capabilities, "nf_conntrack_acct", json_object_new_boolean(probe ? probe->nf_conntrack_acct : false));
	json_object_object_add(capabilities, "flowtable_counter", json_object_new_boolean(probe ? probe->flowtable_counter : false));
	json_object_object_add(capabilities, "tc", json_object_new_boolean(probe ? probe->tc : false));
	json_object_object_add(capabilities, "tc_clsact", json_object_new_boolean(probe ? probe->tc_clsact : false));
	json_object_object_add(capabilities, "existing_tc_filters", json_object_new_boolean(probe ? probe->existing_tc_filters : false));
	json_object_object_add(capabilities, "ifb", json_object_new_boolean(probe ? probe->ifb : false));
	json_object_object_add(capabilities, "sqm", json_object_new_boolean(probe ? probe->sqm : false));
	json_object_object_add(capabilities, "qosify", json_object_new_boolean(probe ? probe->qosify : false));
	json_object_object_add(capabilities, "openclash", json_object_new_boolean(probe ? probe->openclash : false));
	json_object_object_add(capabilities, "openclash_fake_ip", json_object_new_boolean(probe ? probe->openclash_fake_ip : false));
	json_object_object_add(capabilities, "openclash_tun_mix", json_object_new_boolean(probe ? probe->openclash_tun_mix : false));
	json_object_object_add(capabilities, "openclash_redirect_dns", json_object_new_boolean(probe ? probe->openclash_redirect_dns : false));
	json_object_object_add(capabilities, "openclash_dns_chain_complete", json_object_new_boolean(probe ? (!probe->openclash_redirect_dns || probe->openclash_dnsmasq_chain) : false));
	json_object_object_add(capabilities, "openclash_router_self_proxy", json_object_new_boolean(probe ? probe->openclash_router_self_proxy : false));
	json_object_object_add(capabilities, "openclash_udp_proxy", json_object_new_boolean(probe ? probe->openclash_udp_proxy : false));
	json_object_object_add(capabilities, "openclash_ipv6", json_object_new_boolean(probe ? probe->openclash_ipv6 : false));
	json_object_object_add(capabilities, "dae", json_object_new_boolean(probe ? probe->dae : false));
	json_object_object_add(capabilities, "homeproxy", json_object_new_boolean(probe ? probe->homeproxy : false));
	json_object_object_add(capabilities, "lan_bridge", json_object_new_boolean(probe ? probe->lan_bridge : false));
	json_object_object_add(capabilities, "vlan", json_object_new_boolean(probe ? probe->vlan : false));
	json_object_object_add(capabilities, "wlan", json_object_new_boolean(probe ? probe->wlan : false));
	json_object_object_add(capabilities, "lan_edge", json_object_new_boolean(probe ? probe->lan_edge : false));
	json_object_object_add(capabilities, "safe_attach", json_object_new_boolean(probe ? probe->safe_attach : false));
	json_object_object_add(capabilities, "map_full", json_object_new_boolean(probe ? probe->map_full : false));
	json_object_object_add(parent, "capabilities", capabilities);
}

static void add_capabilities(struct json_object *parent)
{
	add_capabilities_from_values(parent, false, enable_conntrack_fallback, false, NULL);
}

static void add_stub_warning(struct json_object *parent)
{
	struct json_object *warnings = json_object_new_array();

	json_object_array_add(warnings, json_object_new_string("stub_no_live_metrics"));
	if (refresh_interval_clamped)
		json_object_array_add(warnings, json_object_new_string("refresh_interval_below_minimum"));
	json_object_object_add(parent, "warnings", warnings);
}

static void add_stub_evidence(struct json_object *parent, const char *method)
{
	struct json_object *evidence = json_object_new_object();

	json_object_object_add(evidence, "source", json_object_new_string("lanspeedd_stub"));
	json_object_object_add(evidence, "method", json_object_new_string(method));
	json_object_object_add(evidence, "fixture_safe", json_object_new_boolean(true));
	json_object_object_add(evidence, "live_metrics", json_object_new_boolean(false));
	json_object_object_add(evidence, "refresh_interval_min_ms", json_object_new_int(MIN_REFRESH_INTERVAL_MS));
	json_object_object_add(evidence, "refresh_interval_clamped", json_object_new_boolean(refresh_interval_clamped));
	json_object_object_add(parent, "evidence", evidence);
}

static void add_clients_identity_evidence(struct json_object *parent)
{
	struct json_object *evidence = json_object_new_object();
	struct json_object *identity_model = json_object_new_object();
	struct json_object *primary_key = json_object_new_array();
	struct json_object *sources = json_object_new_array();
	struct json_object *direction = json_object_new_object();
	struct json_object *excluded = json_object_new_array();

	json_object_object_add(evidence, "source", json_object_new_string("lanspeedd_stub"));
	json_object_object_add(evidence, "method", json_object_new_string("clients"));
	json_object_object_add(evidence, "fixture_safe", json_object_new_boolean(true));
	json_object_object_add(evidence, "live_metrics", json_object_new_boolean(false));

	json_object_array_add(primary_key, json_object_new_string("mac"));
	json_object_array_add(primary_key, json_object_new_string("zone"));
	json_object_object_add(identity_model, "primary_key", primary_key);
	json_object_object_add(identity_model, "attached_fields", json_object_new_string("ips,hostname,interface,last_seen"));
	json_object_object_add(identity_model, "ip_identity", json_object_new_string("addresses are attributes only, not unique identity keys"));

	json_object_array_add(sources, json_object_new_string("dhcp_lease"));
	json_object_array_add(sources, json_object_new_string("arp_nd_neighbor"));
	json_object_array_add(sources, json_object_new_string("hostapd_nl80211"));
	json_object_array_add(sources, json_object_new_string("netifd_ubus"));
	json_object_object_add(identity_model, "merge_sources", sources);

	json_object_object_add(direction, "tx_bps", json_object_new_string("client-originated traffic from the client point of view"));
	json_object_object_add(direction, "rx_bps", json_object_new_string("traffic to client from the client point of view"));
	json_object_object_add(identity_model, "direction", direction);

	json_object_array_add(excluded, json_object_new_string("router_mac"));
	json_object_array_add(excluded, json_object_new_string("broadcast"));
	json_object_array_add(excluded, json_object_new_string("multicast"));
	json_object_array_add(excluded, json_object_new_string("arp"));
	json_object_array_add(excluded, json_object_new_string("nd"));
	json_object_array_add(excluded, json_object_new_string("dae0"));
	json_object_array_add(excluded, json_object_new_string("dae0peer"));
	json_object_array_add(excluded, json_object_new_string("tun"));
	json_object_array_add(excluded, json_object_new_string("ppp"));
	json_object_array_add(excluded, json_object_new_string("wg"));
	json_object_object_add(identity_model, "excluded_from_clients", excluded);

	json_object_object_add(evidence, "identity_model", identity_model);
	json_object_object_add(parent, "evidence", evidence);
}


static uint64_t monotonic_time_ms(void)
{
	struct timeval tv;

	if (gettimeofday(&tv, NULL) != 0)
		return 0;

	return (uint64_t)tv.tv_sec * 1000ULL + (uint64_t)tv.tv_usec / 1000ULL;
}

static bool valid_mac_address(const char *mac)
{
	bool any_non_zero = false;
	bool any_not_ff = false;
	size_t i;

	if (!mac || strlen(mac) != 17)
		return false;

	for (i = 0; i < 17; i++) {
		if ((i + 1) % 3 == 0) {
			if (mac[i] != ':')
				return false;
			continue;
		}

		if (!isxdigit((unsigned char)mac[i]))
			return false;
		if (mac[i] != '0')
			any_non_zero = true;
		if (tolower((unsigned char)mac[i]) != 'f')
			any_not_ff = true;
	}

	return any_non_zero && any_not_ff;
}

static void normalize_mac_address(char *mac)
{
	size_t i;

	for (i = 0; mac && mac[i]; i++)
		mac[i] = (char)tolower((unsigned char)mac[i]);
}

static void derive_zone_from_ifname(const char *ifname, char *zone, size_t zone_size)
{
	if (!zone || !zone_size)
		return;

	if (ifname && (!strncmp(ifname, "br-lan", 6) || !strncmp(ifname, "lan", 3) ||
	    !strncmp(ifname, "wlan", 4)))
		snprintf(zone, zone_size, "lan");
	else if (ifname && ifname[0])
		snprintf(zone, zone_size, "%s", ifname);
	else
		snprintf(zone, zone_size, "lan");
}

/* ------------------------------------------------------------------
 * Hostname cache
 *
 * Resolves client hostnames from (in priority order):
 *   1. /tmp/dhcp.leases     dnsmasq DHCPv4 leases, MAC-keyed  (4th column)
 *   2. /tmp/hosts directory dnsmasq auto-generated host files (IP host ...)
 *   3. /etc/hosts           admin overrides                   (IP host ...)
 *
 * The cache keeps two flat arrays: one MAC-keyed and one IP-keyed, each
 * capped at HOSTNAME_CACHE_MAX.  It is refreshed at most every
 * HOSTNAME_REFRESH_MS and whenever any of the source files' mtimes move.
 * All entries are lower-cased; leases with hostname "*" are ignored.
 * ------------------------------------------------------------------ */

struct hostname_by_mac {
	char mac[MAC_STR_LEN];
	char name[HOSTNAME_STR_LEN];
};

struct hostname_by_ip {
	char ip[IP_STR_LEN];
	char name[HOSTNAME_STR_LEN];
};

static struct hostname_by_mac hostname_mac_cache[HOSTNAME_CACHE_MAX];
static size_t hostname_mac_cache_count;
static struct hostname_by_ip hostname_ip_cache[HOSTNAME_CACHE_MAX];
static size_t hostname_ip_cache_count;
static uint64_t hostname_cache_refresh_ms;
static time_t hostname_cache_leases_mtime;
static time_t hostname_cache_etchosts_mtime;
static time_t hostname_cache_hostsdir_mtime;

static bool hostname_valid(const char *name)
{
	size_t i;

	if (!name || !name[0])
		return false;
	if (!strcmp(name, "*") || !strcmp(name, "-"))
		return false;

	for (i = 0; name[i]; i++) {
		unsigned char c = (unsigned char)name[i];
		if (isspace(c))
			return false;
	}
	return true;
}

static void hostname_cache_add_mac(const char *mac, const char *name)
{
	size_t i;

	if (!valid_mac_address(mac) || !hostname_valid(name))
		return;
	if (hostname_mac_cache_count >= HOSTNAME_CACHE_MAX)
		return;

	for (i = 0; i < hostname_mac_cache_count; i++) {
		if (!strcmp(hostname_mac_cache[i].mac, mac)) {
			snprintf(hostname_mac_cache[i].name,
			         sizeof(hostname_mac_cache[i].name), "%s", name);
			return;
		}
	}

	snprintf(hostname_mac_cache[hostname_mac_cache_count].mac,
	         sizeof(hostname_mac_cache[hostname_mac_cache_count].mac), "%s", mac);
	snprintf(hostname_mac_cache[hostname_mac_cache_count].name,
	         sizeof(hostname_mac_cache[hostname_mac_cache_count].name), "%s", name);
	hostname_mac_cache_count++;
}

static void hostname_cache_add_ip(const char *ip, const char *name)
{
	size_t i;

	if (!ip || !ip[0] || !hostname_valid(name))
		return;
	if (hostname_ip_cache_count >= HOSTNAME_CACHE_MAX)
		return;

	for (i = 0; i < hostname_ip_cache_count; i++) {
		if (!strcmp(hostname_ip_cache[i].ip, ip)) {
			/* do not override earlier higher-priority entry */
			return;
		}
	}

	snprintf(hostname_ip_cache[hostname_ip_cache_count].ip,
	         sizeof(hostname_ip_cache[hostname_ip_cache_count].ip), "%s", ip);
	snprintf(hostname_ip_cache[hostname_ip_cache_count].name,
	         sizeof(hostname_ip_cache[hostname_ip_cache_count].name), "%s", name);
	hostname_ip_cache_count++;
}

static void hostname_cache_parse_leases(void)
{
	FILE *file;
	char line[512];

	file = fopen(DHCP_LEASES_PATH, "r");
	if (!file)
		return;

	while (fgets(line, sizeof(line), file)) {
		unsigned long ts;
		char mac[MAC_STR_LEN];
		char ip[IP_STR_LEN];
		char name[HOSTNAME_STR_LEN];

		if (sscanf(line, "%lu %17s %45s %63s", &ts, mac, ip, name) != 4)
			continue;

		normalize_mac_address(mac);
		hostname_cache_add_mac(mac, name);
		hostname_cache_add_ip(ip, name);
	}

	fclose(file);
}

static void hostname_cache_parse_hosts_file(const char *path)
{
	FILE *file;
	char line[512];

	file = fopen(path, "r");
	if (!file)
		return;

	while (fgets(line, sizeof(line), file)) {
		char ip[IP_STR_LEN];
		char name[HOSTNAME_STR_LEN];
		char *hash;

		hash = strchr(line, '#');
		if (hash)
			*hash = '\0';

		if (sscanf(line, "%45s %63s", ip, name) != 2)
			continue;
		if (ip[0] == '\0' || !strcmp(ip, "127.0.0.1") || !strcmp(ip, "::1"))
			continue;

		hostname_cache_add_ip(ip, name);
	}

	fclose(file);
}

static void hostname_cache_parse_hosts_dir(void)
{
	DIR *dir;
	struct dirent *entry;
	char path[PATH_MAX];

	dir = opendir(HOSTS_DIR);
	if (!dir)
		return;

	while ((entry = readdir(dir))) {
		if (entry->d_name[0] == '.')
			continue;

		snprintf(path, sizeof(path), HOSTS_DIR "/%s", entry->d_name);
		hostname_cache_parse_hosts_file(path);
	}

	closedir(dir);
}

static time_t stat_mtime(const char *path)
{
	struct stat st;

	if (stat(path, &st) != 0)
		return 0;
	return st.st_mtime;
}

static time_t dir_latest_mtime(const char *path)
{
	DIR *dir;
	struct dirent *entry;
	time_t latest = 0;
	char child[PATH_MAX];
	struct stat st;

	if (stat(path, &st) == 0)
		latest = st.st_mtime;

	dir = opendir(path);
	if (!dir)
		return latest;

	while ((entry = readdir(dir))) {
		if (entry->d_name[0] == '.')
			continue;
		snprintf(child, sizeof(child), "%s/%s", path, entry->d_name);
		if (stat(child, &st) == 0 && st.st_mtime > latest)
			latest = st.st_mtime;
	}

	closedir(dir);
	return latest;
}

static void hostname_cache_refresh(bool force)
{
	uint64_t now_ms = monotonic_time_ms();
	time_t leases_mtime = stat_mtime(DHCP_LEASES_PATH);
	time_t etchosts_mtime = stat_mtime(ETC_HOSTS_PATH);
	time_t hostsdir_mtime = dir_latest_mtime(HOSTS_DIR);
	bool changed;

	changed = force ||
	          leases_mtime != hostname_cache_leases_mtime ||
	          etchosts_mtime != hostname_cache_etchosts_mtime ||
	          hostsdir_mtime != hostname_cache_hostsdir_mtime;

	if (!changed && hostname_cache_refresh_ms &&
	    now_ms - hostname_cache_refresh_ms < HOSTNAME_REFRESH_MS)
		return;

	hostname_mac_cache_count = 0;
	hostname_ip_cache_count = 0;

	/* order matters: leases first (most authoritative for clients) */
	hostname_cache_parse_leases();
	hostname_cache_parse_hosts_dir();
	hostname_cache_parse_hosts_file(ETC_HOSTS_PATH);

	hostname_cache_refresh_ms = now_ms;
	hostname_cache_leases_mtime = leases_mtime;
	hostname_cache_etchosts_mtime = etchosts_mtime;
	hostname_cache_hostsdir_mtime = hostsdir_mtime;
}

static const char *hostname_lookup_mac(const char *mac)
{
	size_t i;

	if (!valid_mac_address(mac))
		return NULL;
	for (i = 0; i < hostname_mac_cache_count; i++) {
		if (!strcmp(hostname_mac_cache[i].mac, mac))
			return hostname_mac_cache[i].name;
	}
	return NULL;
}

static const char *hostname_lookup_ip(const char *ip)
{
	size_t i;

	if (!ip || !ip[0])
		return NULL;
	for (i = 0; i < hostname_ip_cache_count; i++) {
		if (!strcmp(hostname_ip_cache[i].ip, ip))
			return hostname_ip_cache[i].name;
	}
	return NULL;
}

static const char *hostname_lookup(const char *mac, const char *const *ips, size_t ip_count)
{
	const char *name;
	size_t i;

	name = hostname_lookup_mac(mac);
	if (name)
		return name;

	for (i = 0; i < ip_count; i++) {
		name = hostname_lookup_ip(ips[i]);
		if (name)
			return name;
	}
	return NULL;
}

static size_t load_arp_table(struct arp_entry *entries, size_t max_entries,
			     struct json_object *warnings)
{
	FILE *file;
	char line[256];
	size_t count = 0;

	file = fopen(ARP_PROCFS_PATH, "r");
	if (!file) {
		add_string_unique(warnings, "conntrack_unavailable");
		return 0;
	}

	if (!fgets(line, sizeof(line), file)) {
		fclose(file);
		add_string_unique(warnings, "conntrack_unavailable");
		return 0;
	}

	while (count < max_entries && fgets(line, sizeof(line), file)) {
		char ip[IP_STR_LEN];
		char hw_type[16];
		char flags[16];
		char mac[MAC_STR_LEN];
		char mask[32];
		char ifname[IFNAME_STR_LEN];
		unsigned long flag_value;

		if (sscanf(line, "%45s %15s %15s %17s %31s %31s",
		           ip, hw_type, flags, mac, mask, ifname) != 6)
			continue;

		flag_value = strtoul(flags, NULL, 0);
		if (flag_value == 0 || !valid_mac_address(mac))
			continue;
		if (ifname_is_excluded_identity_source(ifname))
			continue;

		normalize_mac_address(mac);
		snprintf(entries[count].ip, sizeof(entries[count].ip), "%s", ip);
		snprintf(entries[count].mac, sizeof(entries[count].mac), "%s", mac);
		snprintf(entries[count].ifname, sizeof(entries[count].ifname), "%s", ifname);
		derive_zone_from_ifname(ifname, entries[count].zone, sizeof(entries[count].zone));
		count++;
	}

	fclose(file);
	return count;
}

static const struct arp_entry *find_arp_entry(const struct arp_entry *entries,
					      size_t count, const char *ip)
{
	size_t i;

	for (i = 0; i < count; i++) {
		if (!strcmp(entries[i].ip, ip))
			return &entries[i];
	}

	return NULL;
}

static bool parse_conntrack_procfs_line(const char *line,
					struct conntrack_flow_sample *flow)
{
	char buffer[CONNTRACK_LINE_MAX];
	char *saveptr = NULL;
	char *token;
	int src_index = 0;
	int bytes_index = 0;
	int token_index = 0;

	if (!line || !flow)
		return false;

	memset(flow, 0, sizeof(*flow));
	snprintf(buffer, sizeof(buffer), "%s", line);

	for (token = strtok_r(buffer, " \t\r\n", &saveptr); token;
	     token = strtok_r(NULL, " \t\r\n", &saveptr)) {
		/* Token 2: protocol name (tcp/udp/icmp/...) */
		if (token_index == 2) {
			snprintf(flow->protocol, sizeof(flow->protocol), "%s", token);
			flow->is_tcp = (strcmp(token, "tcp") == 0);
			flow->is_udp = (strcmp(token, "udp") == 0);
		}

		/* Token 5: connection state for TCP (ESTABLISHED/TIME_WAIT/etc) */
		if (token_index == 5 && flow->is_tcp) {
			snprintf(flow->tcp_state, sizeof(flow->tcp_state), "%s", token);
		}

		if (!strncmp(token, "src=", 4)) {
			if (src_index == 0) {
				snprintf(flow->orig_src, sizeof(flow->orig_src), "%s", token + 4);
				flow->has_orig_src = true;
			}
			src_index++;
		} else if (!strncmp(token, "bytes=", 6)) {
			char *end = NULL;
			uint64_t value = strtoull(token + 6, &end, 10);

			if (end == token + 6) {
				token_index++;
				continue;
			}
			if (bytes_index == 0) {
				flow->orig_bytes = value;
				flow->has_orig_bytes = true;
			} else if (bytes_index == 1)
				flow->reply_bytes = value;
			bytes_index++;
		} else if (!strcmp(token, "[ASSURED]")) {
			flow->assured = true;
		}

		token_index++;
	}

	return flow->has_orig_src && flow->has_orig_bytes;
}

static struct conntrack_client_sample *find_conntrack_client_sample(
	struct conntrack_client_sample *samples, size_t count, const char *identity_key)
{
	size_t i;

	for (i = 0; i < count; i++) {
		if (!strcmp(samples[i].identity_key, identity_key))
			return &samples[i];
	}

	return NULL;
}

static const struct conntrack_client_sample *find_previous_conntrack_sample(
	const char *identity_key)
{
	size_t i;

	for (i = 0; i < previous_conntrack_sample_count; i++) {
		if (!strcmp(previous_conntrack_samples[i].identity_key, identity_key))
			return &previous_conntrack_samples[i];
	}

	return NULL;
}

static void add_client_ip_unique(struct conntrack_client_sample *sample, const char *ip)
{
	size_t i;

	if (!sample || !ip || !ip[0])
		return;

	for (i = 0; i < sample->ip_count; i++) {
		if (!strcmp(sample->ips[i], ip))
			return;
	}

	if (sample->ip_count >= MAX_CLIENT_IPS)
		return;

	snprintf(sample->ips[sample->ip_count], sizeof(sample->ips[sample->ip_count]), "%s", ip);
	sample->ip_count++;
}

static bool add_conntrack_flow_to_samples(struct conntrack_client_sample *samples,
					  size_t *sample_count, size_t max_samples,
					  const struct arp_entry *arp_entries, size_t arp_count,
					  const struct conntrack_flow_sample *flow,
					  uint64_t now_ms, struct conntrack_collect_stats *stats)
{
	const struct arp_entry *arp;
	struct conntrack_client_sample *sample;
	char identity_key[IDENTITY_KEY_STR_LEN];

	if (!flow || !flow->has_orig_src || !flow->has_orig_bytes)
		return false;

	arp = find_arp_entry(arp_entries, arp_count, flow->orig_src);
	if (!arp) {
		if (stats)
			stats->skipped_no_arp++;
		return true;
	}

	snprintf(identity_key, sizeof(identity_key), "%s@%s", arp->mac, arp->zone);
	sample = find_conntrack_client_sample(samples, *sample_count, identity_key);
	if (!sample) {
		if (*sample_count >= max_samples)
			return true;
		sample = &samples[*sample_count];
		memset(sample, 0, sizeof(*sample));
		snprintf(sample->mac, sizeof(sample->mac), "%s", arp->mac);
		snprintf(sample->identity_key, sizeof(sample->identity_key), "%s", identity_key);
		snprintf(sample->zone, sizeof(sample->zone), "%s", arp->zone);
		snprintf(sample->ifname, sizeof(sample->ifname), "%s", arp->ifname);
		(*sample_count)++;
	}

	add_client_ip_unique(sample, arp->ip);
	sample->tx_bytes += flow->orig_bytes;
	sample->rx_bytes += flow->reply_bytes;
	sample->last_seen_ms = now_ms;

	if (flow->is_tcp && strcmp(flow->tcp_state, "ESTABLISHED") == 0 && flow->assured)
		sample->tcp_conns++;
	else if (flow->is_udp)
		sample->udp_conns++;

	if (stats)
		stats->entries_matched++;

	return true;
}

static bool open_conntrack_procfs(FILE **file, char *source_path, size_t source_path_size)
{
	*file = fopen(CONNTRACK_PROCFS_PATH, "r");
	if (*file) {
		snprintf(source_path, source_path_size, "%s", CONNTRACK_PROCFS_PATH);
		return true;
	}

	*file = fopen(CONNTRACK_LEGACY_PROCFS_PATH, "r");
	if (*file) {
		snprintf(source_path, source_path_size, "%s", CONNTRACK_LEGACY_PROCFS_PATH);
		return true;
	}

	return false;
}

static bool read_conntrack_procfs_snapshot(struct conntrack_client_sample *samples,
					   size_t *sample_count, size_t max_samples,
					   uint64_t now_ms, struct json_object *warnings,
					   struct conntrack_collect_stats *stats)
{
	struct arp_entry arp_entries[DEFAULT_MAX_CLIENTS];
	size_t arp_count;
	FILE *file = NULL;
	char line[CONNTRACK_LINE_MAX];

	*sample_count = 0;
	memset(stats, 0, sizeof(*stats));
	arp_count = load_arp_table(arp_entries, ARRAY_SIZE(arp_entries), warnings);
	if (arp_count == 0)
		return false;

	if (!open_conntrack_procfs(&file, stats->source_path, sizeof(stats->source_path))) {
		add_string_unique(warnings, "conntrack_unavailable");
		return false;
	}

	stats->procfs_read = true;
	while (fgets(line, sizeof(line), file)) {
		struct conntrack_flow_sample flow;

		stats->entries_seen++;

		if (!parse_conntrack_procfs_line(line, &flow)) {
			stats->malformed_lines++;
			continue;
		}

		add_conntrack_flow_to_samples(samples, sample_count, max_samples,
					      arp_entries, arp_count, &flow, now_ms, stats);
	}

	fclose(file);
	stats->current_clients = *sample_count;
	return true;
}

static uint64_t delta_bps(uint64_t current, uint64_t previous, uint64_t delta_ms,
			  bool *counter_anomaly)
{
	if (current < previous) {
		if (counter_anomaly)
			*counter_anomaly = true;
		return 0;
	}

	if (delta_ms == 0)
		return 0;

	return ((current - previous) * 8ULL * 1000ULL) / delta_ms;
}

static void add_conntrack_common_warnings(const struct runtime_probe *probe,
					  struct json_object *warnings)
{
	add_string_unique(warnings, "conntrack_routed_nat_only");
	if (!probe->flowtable_counter)
		add_string_unique(warnings, "flowtable_counter_missing");
	if (probe->nlbwmon)
		add_string_unique(warnings, "nlbwmon_counter_conflict");
	if (probe->openclash || probe->dae || probe->homeproxy)
		add_string_unique(warnings, "proxy_path_confidence_low");
	if (probe->openclash_fake_ip)
		add_string_unique(warnings, "openclash_fake_ip_low_remote_confidence");
	if (probe->openclash_tun_mix)
		add_string_unique(warnings, "openclash_tun_conntrack_low_confidence");
	if (probe->openclash_dns_chain_incomplete)
		add_string_unique(warnings, "openclash_dns_chain_incomplete");
	if (probe->openclash_router_self_proxy)
		add_string_unique(warnings, "openclash_router_self_proxy_detected");
	if (probe->sqm || probe->qosify || probe->ifb)
		add_string_unique(warnings, "qos_ifb_confidence_low");
	if (probe->hardware_flow_offload || probe->software_flow_offload) {
		/* NSS ECM / PPE syncs counters back to conntrack; downgrade
		 * the blanket "flow_offload_confidence_low" to a softer
		 * warning that reflects the actual sync cadence. */
		if (probe->nss_present && (probe->nss_ecm_active || probe->nss_ppe_active))
			add_string_unique(warnings, "nss_ecm_sync_cadence");
		else
			add_string_unique(warnings, "flow_offload_confidence_low");
	}
}

static void add_conntrack_identity_model(struct json_object *evidence)
{
	struct json_object *identity = json_object_new_object();
	struct json_object *primary_key = json_object_new_array();

	json_object_array_add(primary_key, json_object_new_string("mac"));
	json_object_array_add(primary_key, json_object_new_string("zone"));
	json_object_object_add(identity, "primary_key", primary_key);
	json_object_object_add(identity, "ip_identity", json_object_new_string("LAN IPs are attributes mapped through ARP, never primary identity keys"));
	json_object_object_add(identity, "mac_source", json_object_new_string(ARP_PROCFS_PATH));
	json_object_object_add(identity, "excluded_interfaces", json_object_new_string("dae0,dae0peer,tun*,ppp*,wg*"));
	json_object_object_add(identity, "missing_mac_policy", json_object_new_string("skip_conntrack_entry_without_fabricating_client"));
	json_object_object_add(evidence, "identity_model", identity);
}

static void add_conntrack_clients_evidence(struct json_object *root,
					   const struct runtime_probe *probe,
					   struct json_object *warnings,
					   const struct conntrack_collect_stats *stats,
					   bool active)
{
	struct json_object *evidence = json_object_new_object();
	struct json_object *sources = json_object_new_array();
	struct json_object *forbidden = json_object_new_array();
	struct json_object *router_self = json_object_new_object();

	json_object_array_add(sources, json_object_new_string("procfs:/proc/net/nf_conntrack"));
	json_object_array_add(sources, json_object_new_string("procfs:/proc/net/ip_conntrack"));
	json_object_array_add(sources, json_object_new_string("procfs:/proc/net/arp"));
	json_object_array_add(forbidden, json_object_new_string("firewall_forward_chain_counters"));
	json_object_array_add(forbidden, json_object_new_string("iptables_forward_chain_counters"));
	json_object_array_add(forbidden, json_object_new_string("nft_forward_chain_counters"));
	json_object_array_add(forbidden, json_object_new_string("nlbwmon_counters"));

	json_object_object_add(evidence, "source", json_object_new_string("lanspeedd_procfs_conntrack_acct"));
	json_object_object_add(evidence, "method", json_object_new_string("clients"));
	json_object_object_add(evidence, "read_only", json_object_new_boolean(true));
	json_object_object_add(evidence, "collector_mode", json_object_new_string("conntrack"));
	json_object_object_add(evidence, "mode", json_object_new_string("Degraded"));
	json_object_object_add(evidence, "active", json_object_new_boolean(active));
	json_object_object_add(evidence, "live_metrics", json_object_new_boolean(false));
	json_object_object_add(evidence, "bpf_runtime_metrics", json_object_new_boolean(probe->bpf_runtime_metrics));
	json_object_object_add(evidence, "confidence", json_object_new_string(conntrack_fallback_confidence(probe)));
	json_object_object_add(evidence, "coverage", json_object_new_string("routed_nat_only"));
	json_object_object_add(evidence, "coverage_warning", json_object_new_string("conntrack_routed_nat_only"));
	json_object_object_add(evidence, "counter_source", json_object_new_string("procfs_conntrack_acct_orig_reply_bytes"));
	json_object_object_add(evidence, "sources", sources);
	json_object_object_add(evidence, "forbidden_sources", forbidden);
	json_object_object_add(evidence, "nlbwmon_read_counters", json_object_new_boolean(false));
	json_object_object_add(evidence, "nf_conntrack_acct", json_object_new_boolean(probe->nf_conntrack_acct));
	json_object_object_add(evidence, "nf_conntrack_acct_present", json_object_new_boolean(probe->nf_conntrack_acct_present));
	json_object_object_add(evidence, "flowtable_counter", json_object_new_boolean(probe->flowtable_counter));
	json_object_object_add(router_self, "bucket", json_object_new_string("router_self"));
	json_object_object_add(router_self, "alias", json_object_new_string("local_router"));
	json_object_object_add(router_self, "enabled", json_object_new_boolean(probe->openclash_router_self_proxy));
	json_object_object_add(router_self, "identity_key", json_object_new_string("router_self@local_router"));
	json_object_object_add(router_self, "client_attribution", json_object_new_string("never_attribute_to_lan_client"));
	json_object_object_add(evidence, "router_self", router_self);
	if (stats) {
		json_object_object_add(evidence, "procfs_read", json_object_new_boolean(stats->procfs_read));
		json_object_object_add(evidence, "source_path", json_object_new_string(stats->source_path[0] ? stats->source_path : ""));
		json_object_object_add(evidence, "snapshot_pending", json_object_new_boolean(stats->snapshot_pending));
		json_object_object_add(evidence, "current_clients", json_object_new_int64((int64_t)stats->current_clients));
		json_object_object_add(evidence, "emitted_clients", json_object_new_int64((int64_t)stats->emitted_clients));
		json_object_object_add(evidence, "skipped_no_arp", json_object_new_int64((int64_t)stats->skipped_no_arp));
		json_object_object_add(evidence, "malformed_lines", json_object_new_int64((int64_t)stats->malformed_lines));
	}
	json_object_object_add(evidence, "warnings", warnings);
	add_conntrack_identity_model(evidence);
	json_object_object_add(root, "evidence", evidence);
}

static void emit_conntrack_clients(struct json_object *root,
				   struct json_object *clients,
				   const struct runtime_probe *probe,
				   struct conntrack_client_sample *current,
				   size_t current_count, uint64_t now_ms,
				   struct json_object *base_warnings,
				   struct conntrack_collect_stats *stats)
{
	uint64_t delta_ms = previous_conntrack_snapshot_valid ?
		(now_ms - previous_conntrack_snapshot_ms) : 0;
	uint64_t tcp_conns_total = 0;
	uint64_t udp_conns_total = 0;
	size_t i;

	if (!previous_conntrack_snapshot_valid) {
		stats->snapshot_pending = true;
		add_string_unique(base_warnings, "conntrack_snapshot_pending");
	} else if (now_ms < previous_conntrack_snapshot_ms) {
		stats->snapshot_pending = true;
		add_string_unique(base_warnings, "time_rollback");
		delta_ms = 0;
	}

	for (i = 0; i < current_count; i++) {
		const struct conntrack_client_sample *previous;
		struct json_object *client;
		struct json_object *ips;
		struct json_object *warnings;
		bool counter_anomaly = false;
		uint64_t tx_bps = 0;
		uint64_t rx_bps = 0;
		size_t ip_index;

		previous = find_previous_conntrack_sample(current[i].identity_key);
		if (previous_conntrack_snapshot_valid && previous) {
			tx_bps = delta_bps(current[i].tx_bytes, previous->tx_bytes, delta_ms, &counter_anomaly);
			rx_bps = delta_bps(current[i].rx_bytes, previous->rx_bytes, delta_ms, &counter_anomaly);
		}
		if (counter_anomaly)
			add_string_unique(base_warnings, "counter_anomaly");

		client = json_object_new_object();
		ips = json_object_new_array();
		warnings = json_object_get(base_warnings);
		for (ip_index = 0; ip_index < current[i].ip_count; ip_index++)
			json_object_array_add(ips, json_object_new_string(current[i].ips[ip_index]));

		json_object_object_add(client, "mac", json_object_new_string(current[i].mac));
		json_object_object_add(client, "identity_key", json_object_new_string(current[i].identity_key));
		json_object_object_add(client, "zone", json_object_new_string(current[i].zone));
		json_object_object_add(client, "interface", json_object_new_string(current[i].ifname));
		json_object_object_add(client, "ips", ips);
		{
			const char *ip_ptrs[MAX_CLIENT_IPS];
			const char *name;
			size_t k;
			for (k = 0; k < current[i].ip_count; k++)
				ip_ptrs[k] = current[i].ips[k];
			name = hostname_lookup(current[i].mac, ip_ptrs, current[i].ip_count);
			json_object_object_add(client, "hostname",
			                       name ? json_object_new_string(name) : NULL);
		}
		json_object_object_add(client, "rx_bps", json_object_new_int64((int64_t)rx_bps));
		json_object_object_add(client, "tx_bps", json_object_new_int64((int64_t)tx_bps));
		json_object_object_add(client, "rx_bytes", json_object_new_int64((int64_t)current[i].rx_bytes));
		json_object_object_add(client, "tx_bytes", json_object_new_int64((int64_t)current[i].tx_bytes));
		json_object_object_add(client, "tcp_conns", json_object_new_int64((int64_t)current[i].tcp_conns));
		json_object_object_add(client, "udp_conns", json_object_new_int64((int64_t)current[i].udp_conns));
		json_object_object_add(client, "sample_ms", json_object_new_int64((int64_t)now_ms));
		json_object_object_add(client, "last_seen", json_object_new_int64((int64_t)current[i].last_seen_ms));
		json_object_object_add(client, "collector_mode",
			json_object_new_string(
				(probe->nss_present && (probe->nss_ecm_active || probe->nss_ppe_active))
					? "conntrack_ecm_sync"
					: "conntrack"));
		json_object_object_add(client, "confidence", json_object_new_string(conntrack_fallback_confidence(probe)));
		json_object_object_add(client, "warnings", warnings);
		json_object_array_add(clients, client);
		stats->emitted_clients++;
		tcp_conns_total += current[i].tcp_conns;
		udp_conns_total += current[i].udp_conns;
	}

	json_object_object_add(root, "tcp_conns_total", json_object_new_int64((int64_t)tcp_conns_total));
	json_object_object_add(root, "udp_conns_total", json_object_new_int64((int64_t)udp_conns_total));
	json_object_object_add(root, "conntrack_entries_seen", json_object_new_int64((int64_t)stats->entries_seen));
	json_object_object_add(root, "conntrack_entries_matched", json_object_new_int64((int64_t)stats->entries_matched));
	json_object_object_add(root, "conntrack_parse_errors", json_object_new_int64((int64_t)stats->malformed_lines));
	json_object_object_add(root, "conn_source", json_object_new_string("conntrack"));
	json_object_object_add(root, "conn_semantics", json_object_new_string("tcp_established_assured_udp_tracked"));

	memcpy(previous_conntrack_samples, current,
	       current_count * sizeof(struct conntrack_client_sample));
	previous_conntrack_sample_count = current_count;
	previous_conntrack_snapshot_ms = now_ms;
	previous_conntrack_snapshot_valid = true;
}

static struct bpf_client_sample *bpf_find_or_insert_client(
	struct bpf_client_sample *samples, size_t *count, size_t max_samples,
	const char *mac, const char *zone, const char *ifname,
	const char *identity_key,
	const struct arp_entry *arp_entries, size_t arp_count)
{
	struct bpf_client_sample *sample;
	size_t i;

	for (i = 0; i < *count; i++) {
		if (!strcmp(samples[i].identity_key, identity_key))
			return &samples[i];
	}

	if (*count >= max_samples)
		return NULL;

	sample = &samples[*count];
	memset(sample, 0, sizeof(*sample));
	snprintf(sample->mac, sizeof(sample->mac), "%s", mac);
	snprintf(sample->identity_key, sizeof(sample->identity_key), "%s", identity_key);
	snprintf(sample->zone, sizeof(sample->zone), "%s", zone);
	snprintf(sample->ifname, sizeof(sample->ifname), "%s", ifname);

	for (i = 0; i < arp_count && sample->ip_count < MAX_CLIENT_IPS; i++) {
		size_t k;
		bool dup = false;

		if (strcasecmp(arp_entries[i].mac, mac))
			continue;
		for (k = 0; k < sample->ip_count; k++) {
			if (!strcmp(sample->ips[k], arp_entries[i].ip)) {
				dup = true;
				break;
			}
		}
		if (!dup)
			snprintf(sample->ips[sample->ip_count++],
				 sizeof(sample->ips[0]), "%.*s",
				 (int)(sizeof(sample->ips[0]) - 1),
				 arp_entries[i].ip);
	}

	(*count)++;
	return sample;
}

static void bpf_collect_samples(void)
{
	struct lanspeed_bpf_sample raw[DEFAULT_MAX_CLIENTS * 2];
	struct arp_entry arp_entries[DEFAULT_MAX_CLIENTS];
	struct json_object *discard_warnings = json_object_new_array();
	size_t raw_count = 0;
	size_t arp_count;
	uint64_t now_ms = monotonic_time_ms();
	size_t max_folded = max_clients > 0 && max_clients < DEFAULT_MAX_CLIENTS ?
			    (size_t)max_clients : DEFAULT_MAX_CLIENTS;
	size_t i;

	if (lanspeed_bpf_read_samples(raw, ARRAY_SIZE(raw), &raw_count) != 0) {
		json_object_put(discard_warnings);
		return;
	}

	memcpy(bpf_previous_samples, bpf_current_samples,
	       bpf_current_sample_count * sizeof(bpf_current_samples[0]));
	bpf_previous_sample_count = bpf_current_sample_count;
	bpf_previous_snapshot_ms = bpf_current_snapshot_ms;
	bpf_previous_snapshot_valid = bpf_previous_snapshot_ms > 0;

	bpf_current_sample_count = 0;
	bpf_current_snapshot_ms = now_ms;

	arp_count = load_arp_table(arp_entries, ARRAY_SIZE(arp_entries),
				   discard_warnings);

	for (i = 0; i < raw_count; i++) {
		char mac_str[MAC_STR_LEN];
		char ifname_buf[IFNAME_STR_LEN];
		char zone[ZONE_STR_LEN];
		char identity_key[IDENTITY_KEY_STR_LEN];
		struct bpf_client_sample *sample;

		snprintf(mac_str, sizeof(mac_str),
			 "%02x:%02x:%02x:%02x:%02x:%02x",
			 raw[i].mac[0], raw[i].mac[1], raw[i].mac[2],
			 raw[i].mac[3], raw[i].mac[4], raw[i].mac[5]);

		if (!valid_mac_address(mac_str))
			continue;

		if (!if_indextoname(raw[i].ifindex, ifname_buf))
			snprintf(ifname_buf, sizeof(ifname_buf), "if%u",
				 raw[i].ifindex);
		if (ifname_is_excluded_identity_source(ifname_buf))
			continue;

		derive_zone_from_ifname(ifname_buf, zone, sizeof(zone));
		snprintf(identity_key, sizeof(identity_key), "%s@%s", mac_str, zone);

		sample = bpf_find_or_insert_client(bpf_current_samples,
						   &bpf_current_sample_count,
						   max_folded, mac_str, zone,
						   ifname_buf, identity_key,
						   arp_entries, arp_count);
		if (!sample)
			break;

		if (raw[i].direction == LANSPEED_BPF_DIR_TX)
			sample->tx_bytes += raw[i].bytes;
		else if (raw[i].direction == LANSPEED_BPF_DIR_RX)
			sample->rx_bytes += raw[i].bytes;
		sample->last_seen_ms = now_ms;
	}

	json_object_put(discard_warnings);
}

static void bpf_collect_tick(struct uloop_timeout *t)
{
	if (bpf_runtime_enabled)
		bpf_collect_samples();
	uloop_timeout_set(t, refresh_interval_ms > 0 ? refresh_interval_ms :
						       DEFAULT_REFRESH_INTERVAL_MS);
}

static void add_bpf_clients_evidence(struct json_object *root,
				     const struct runtime_probe *probe,
				     uint64_t delta_ms, size_t emitted_clients)
{
	struct json_object *evidence = json_object_new_object();
	struct json_object *sources = json_object_new_array();
	const struct lanspeed_bpf_status *status = lanspeed_bpf_get_status();

	(void)probe;

	json_object_array_add(sources, json_object_new_string("bpf:lanspeed_clients"));
	json_object_array_add(sources, json_object_new_string("procfs:/proc/net/arp"));

	json_object_object_add(evidence, "collector_mode", json_object_new_string("bpf"));
	json_object_object_add(evidence, "mode", json_object_new_string("Full"));
	json_object_object_add(evidence, "live_metrics", json_object_new_boolean(true));
	json_object_object_add(evidence, "runtime_attach_map_read_success",
			       json_object_new_boolean(true));
	json_object_object_add(evidence, "bpf_assets_are_evidence_only",
			       json_object_new_boolean(false));
	json_object_object_add(evidence, "sources", sources);
	json_object_object_add(evidence, "delta_ms", json_object_new_int64((int64_t)delta_ms));
	json_object_object_add(evidence, "emitted_clients",
			       json_object_new_int((int)emitted_clients));
	if (status) {
		json_object_object_add(evidence, "bpf_object_path",
				       json_object_new_string(status->object_path));
		json_object_object_add(evidence, "attached_hooks",
				       json_object_new_int((int)status->attached_hook_count));
		json_object_object_add(evidence, "last_sample_count",
				       json_object_new_int((int)status->last_sample_count));
	}
	json_object_object_add(root, "evidence", evidence);
}

static bool collect_bpf_clients(struct json_object *root,
				struct json_object *clients,
				const struct runtime_probe *probe)
{
	uint64_t delta_ms;
	size_t emitted = 0;
	size_t i;

	if (!bpf_runtime_metrics_available(probe))
		return false;
	if (!bpf_previous_snapshot_valid || bpf_current_sample_count == 0)
		return false;
	if (bpf_current_snapshot_ms <= bpf_previous_snapshot_ms)
		return false;
	delta_ms = bpf_current_snapshot_ms - bpf_previous_snapshot_ms;
	if (delta_ms == 0)
		return false;

	for (i = 0; i < bpf_current_sample_count; i++) {
		struct json_object *client = json_object_new_object();
		struct json_object *ips = json_object_new_array();
		struct json_object *warnings = json_object_new_array();
		struct bpf_client_sample *cur = &bpf_current_samples[i];
		struct bpf_client_sample *prev = NULL;
		bool counter_anomaly = false;
		uint64_t tx_bps = 0;
		uint64_t rx_bps = 0;
		size_t j;

		for (j = 0; j < bpf_previous_sample_count; j++) {
			if (!strcmp(bpf_previous_samples[j].identity_key,
				    cur->identity_key)) {
				prev = &bpf_previous_samples[j];
				break;
			}
		}
		if (prev) {
			tx_bps = delta_bps(cur->tx_bytes, prev->tx_bytes,
					   delta_ms, &counter_anomaly);
			rx_bps = delta_bps(cur->rx_bytes, prev->rx_bytes,
					   delta_ms, &counter_anomaly);
		}
		if (counter_anomaly)
			add_string_unique(warnings, "counter_anomaly");

		for (j = 0; j < cur->ip_count; j++)
			json_object_array_add(ips, json_object_new_string(cur->ips[j]));

		json_object_object_add(client, "mac", json_object_new_string(cur->mac));
		json_object_object_add(client, "identity_key",
				       json_object_new_string(cur->identity_key));
		json_object_object_add(client, "zone", json_object_new_string(cur->zone));
		json_object_object_add(client, "interface",
				       json_object_new_string(cur->ifname));
		json_object_object_add(client, "ips", ips);
		{
			const char *ip_ptrs[MAX_CLIENT_IPS];
			const char *name;
			size_t k;
			for (k = 0; k < cur->ip_count; k++)
				ip_ptrs[k] = cur->ips[k];
			name = hostname_lookup(cur->mac, ip_ptrs, cur->ip_count);
			json_object_object_add(client, "hostname",
			                       name ? json_object_new_string(name) : NULL);
		}
		json_object_object_add(client, "rx_bps",
				       json_object_new_int64((int64_t)rx_bps));
		json_object_object_add(client, "tx_bps",
				       json_object_new_int64((int64_t)tx_bps));
		json_object_object_add(client, "rx_bytes",
				       json_object_new_int64((int64_t)cur->rx_bytes));
		json_object_object_add(client, "tx_bytes",
				       json_object_new_int64((int64_t)cur->tx_bytes));
		json_object_object_add(client, "sample_ms",
				       json_object_new_int64((int64_t)bpf_current_snapshot_ms));
		json_object_object_add(client, "last_seen",
				       json_object_new_int64((int64_t)cur->last_seen_ms));
		json_object_object_add(client, "collector_mode",
				       json_object_new_string("bpf"));
		json_object_object_add(client, "confidence",
				       json_object_new_string("high"));
		json_object_object_add(client, "warnings", warnings);
		json_object_array_add(clients, client);
		emitted++;
	}

	add_bpf_clients_evidence(root, probe, delta_ms, emitted);
	return true;
}

static bool collect_conntrack_procfs_clients(struct json_object *root,
					     struct json_object *clients,
					     const struct runtime_probe *probe)
{
	struct conntrack_client_sample current[DEFAULT_MAX_CLIENTS];
	struct conntrack_collect_stats stats;
	struct json_object *warnings = json_object_new_array();
	uint64_t now_ms = monotonic_time_ms();
	size_t current_count = 0;
	size_t max_samples = max_clients > 0 && max_clients < DEFAULT_MAX_CLIENTS ?
		(size_t)max_clients : DEFAULT_MAX_CLIENTS;
	bool read_ok;

	if (!conntrack_fallback_active(probe)) {
		add_string_unique(warnings, "live_metrics_unavailable");
		if (!probe->nf_conntrack_acct)
			add_string_unique(warnings, "conntrack_acct_disabled");
		if (!probe->nf_conntrack_acct_present)
			add_string_unique(warnings, "conntrack_unavailable");
		add_conntrack_clients_evidence(root, probe, warnings, NULL, false);
		return false;
	}

	add_conntrack_common_warnings(probe, warnings);
	add_string_unique(warnings, "live_metrics_unavailable");
	if (enable_bpf && probe->safe_attach && !probe->bpf_runtime_metrics)
		add_string_unique(warnings, "bpf_runtime_loader_unavailable");
	read_ok = read_conntrack_procfs_snapshot(current, &current_count, max_samples,
					       now_ms, warnings, &stats);
	if (!read_ok) {
		add_conntrack_clients_evidence(root, probe, warnings, &stats, true);
		return false;
	}

	emit_conntrack_clients(root, clients, probe, current, current_count, now_ms, warnings, &stats);
	add_conntrack_clients_evidence(root, probe, warnings, &stats, true);
	return true;
}

static int send_json_reply(struct ubus_context *ubus, struct ubus_request_data *req,
			   struct json_object *root)
{
	int ret;

	blob_buf_init(&reply, 0);
	blobmsg_add_json_from_string(&reply,
		json_object_to_json_string_ext(root, JSON_C_TO_STRING_PLAIN));
	ret = ubus_send_reply(ubus, req, reply.head);
	json_object_put(root);

	return ret;
}

static int status_method(struct ubus_context *ubus, struct ubus_object *obj,
			 struct ubus_request_data *req, const char *method,
			 struct blob_attr *msg)
{
	struct json_object *root = json_object_new_object();
	struct runtime_probe probe;
	const char *mode;

	(void)obj;
	(void)method;
	(void)msg;

	init_runtime_probe(&probe);
	inspect_runtime(&probe);
	mode = probe_mode(&probe);
	if (strcmp(mode, "Full"))
		add_warning(&probe, "live_metrics_unavailable");
	finish_probe_evidence(&probe, "status");

	json_object_object_add(root, "mode", json_object_new_string(mode));
	json_object_object_add(root, "confidence", json_object_new_string(probe_confidence(&probe, mode)));
	json_object_object_add(root, "warnings", probe.warnings);
	json_object_object_add(root, "evidence", probe.evidence);
	json_object_object_add(root, "refresh_interval_ms", json_object_new_int(refresh_interval_ms));
	json_object_object_add(root, "version", json_object_new_string(LANSPEED_VERSION));
	add_capabilities_from_values(root, enable_bpf && probe.bpf_runtime_metrics,
				     enable_conntrack_fallback,
				     probe.bpf_runtime_metrics, &probe);
	json_object_put(probe.conflicts);

	return send_json_reply(ubus, req, root);
}

static void merge_conntrack_conn_counts(struct json_object *root,
					struct json_object *clients)
{
	struct conntrack_client_sample conn_samples[DEFAULT_MAX_CLIENTS];
	struct conntrack_collect_stats conn_stats;
	struct json_object *discard_warnings = json_object_new_array();
	uint64_t now_ms = monotonic_time_ms();
	size_t conn_count = 0;
	size_t max_samples = max_clients > 0 && max_clients < DEFAULT_MAX_CLIENTS ?
		(size_t)max_clients : DEFAULT_MAX_CLIENTS;
	bool read_ok;
	size_t i, n;
	uint32_t tcp_total = 0;
	uint32_t udp_total = 0;

	read_ok = read_conntrack_procfs_snapshot(conn_samples, &conn_count,
						 max_samples, now_ms,
						 discard_warnings, &conn_stats);
	json_object_put(discard_warnings);

	if (!read_ok)
		return;

	/* Merge connection counts into existing BPF client JSON objects */
	n = json_object_array_length(clients);
	for (i = 0; i < n; i++) {
		struct json_object *client = json_object_array_get_idx(clients, i);
		struct json_object *key_obj = NULL;
		const char *key;
		const struct conntrack_client_sample *cs;

		if (!client)
			continue;
		if (!json_object_object_get_ex(client, "identity_key", &key_obj))
			continue;
		key = json_object_get_string(key_obj);
		if (!key)
			continue;

		cs = find_conntrack_client_sample(conn_samples, conn_count, key);
		if (cs) {
			json_object_object_add(client, "tcp_conns",
					       json_object_new_int((int)cs->tcp_conns));
			json_object_object_add(client, "udp_conns",
					       json_object_new_int((int)cs->udp_conns));
			tcp_total += cs->tcp_conns;
			udp_total += cs->udp_conns;
		} else {
			json_object_object_add(client, "tcp_conns",
					       json_object_new_int(0));
			json_object_object_add(client, "udp_conns",
					       json_object_new_int(0));
		}
	}

	/* Add top-level connection count summary and diagnostics */
	json_object_object_add(root, "tcp_conns_total",
			       json_object_new_int((int)tcp_total));
	json_object_object_add(root, "udp_conns_total",
			       json_object_new_int((int)udp_total));
	json_object_object_add(root, "conntrack_entries_seen",
			       json_object_new_int((int)conn_stats.entries_seen));
	json_object_object_add(root, "conntrack_entries_matched",
			       json_object_new_int((int)conn_stats.entries_matched));
	json_object_object_add(root, "conntrack_parse_errors",
			       json_object_new_int((int)conn_stats.malformed_lines));
	json_object_object_add(root, "conn_source",
			       json_object_new_string("conntrack"));
	json_object_object_add(root, "conn_semantics",
			       json_object_new_string("tcp_established_assured_udp_tracked"));
}

static int clients_method(struct ubus_context *ubus, struct ubus_object *obj,
			  struct ubus_request_data *req, const char *method,
			  struct blob_attr *msg)
{
	struct json_object *root = json_object_new_object();
	struct json_object *clients = json_object_new_array();

	(void)obj;
	(void)method;
	(void)msg;

	json_object_object_add(root, "clients", clients);

	hostname_cache_refresh(false);

	{
		struct runtime_probe probe;
		init_runtime_probe(&probe);
		inspect_runtime(&probe);
		if (!collect_bpf_clients(root, clients, &probe)) {
			collect_conntrack_procfs_clients(root, clients, &probe);
		} else {
			/* BPF provides rate data; additionally scan conntrack
			 * for connection counts only (tcp_conns/udp_conns).
			 * This does NOT overwrite BPF rate fields. */
			merge_conntrack_conn_counts(root, clients);
		}
		free_runtime_probe(&probe);
	}

	return send_json_reply(ubus, req, root);
}

static int health_method(struct ubus_context *ubus, struct ubus_object *obj,
			 struct ubus_request_data *req, const char *method,
			 struct blob_attr *msg)
{
	struct json_object *root = json_object_new_object();
	struct runtime_probe probe;
	const char *mode;

	(void)obj;
	(void)method;
	(void)msg;

	init_runtime_probe(&probe);
	inspect_runtime(&probe);
	mode = probe_mode(&probe);
	if (strcmp(mode, "Full"))
		add_warning(&probe, "live_metrics_unavailable");
	finish_probe_evidence(&probe, "health");

	json_object_object_add(root, "mode", json_object_new_string(mode));
	json_object_object_add(root, "confidence", json_object_new_string(probe_confidence(&probe, mode)));
	add_capabilities_from_values(root, enable_bpf && probe.bpf_runtime_metrics,
				     enable_conntrack_fallback,
				     probe.bpf_runtime_metrics, &probe);
	json_object_object_add(root, "conflicts", probe.conflicts);
	json_object_object_add(root, "warnings", probe.warnings);
	json_object_object_add(root, "evidence", probe.evidence);

	return send_json_reply(ubus, req, root);
}

static bool sysdevice_is_candidate(const char *name)
{
	if (!name || !name[0])
		return false;
	if (!strcmp(name, "lo"))
		return false;
	if (!strncmp(name, "teql", 4))
		return false;
	return true;
}

static bool sysdevice_is_recommended_lan(const char *name)
{
	if (!name || !name[0])
		return false;
	if (!strncmp(name, "wan", 3))
		return false;
	if (!strncmp(name, "pppoe-", 6) || !strncmp(name, "ppp", 3))
		return false;
	if (!strncmp(name, "wg", 2))
		return false;
	if (!strncmp(name, "tun", 3) || !strncmp(name, "tap", 3))
		return false;
	if (!strncmp(name, "utun", 4))
		return false;
	/* nssifb mirrors NSS physical ingress; BPF-attaching it would
	 * double-count mirrored bytes from eth0. Observe-only at most. */
	if (!strcmp(name, "nssifb"))
		return false;
	return true;
}

static bool sysdevice_read_u64(const char *ifname, const char *field, uint64_t *out)
{
	char path[PATH_MAX];
	char buf[64];
	FILE *fp;

	snprintf(path, sizeof(path), "/sys/class/net/%s/%s", ifname, field);
	fp = fopen(path, "r");
	if (!fp)
		return false;
	if (!fgets(buf, sizeof(buf), fp)) {
		fclose(fp);
		return false;
	}
	fclose(fp);
	*out = strtoull(buf, NULL, 10);
	return true;
}

static int sysdevices_method(struct ubus_context *ubus, struct ubus_object *obj,
			     struct ubus_request_data *req, const char *method,
			     struct blob_attr *msg)
{
	struct json_object *root = json_object_new_object();
	struct json_object *devs = json_object_new_array();
	DIR *dir;
	struct dirent *entry;
	size_t i;

	(void)obj;
	(void)method;
	(void)msg;

	dir = opendir("/sys/class/net");
	if (dir) {
		while ((entry = readdir(dir))) {
			const char *name = entry->d_name;
			struct json_object *d;
			char path[PATH_MAX];
			struct stat st;
			bool is_bridge, has_upper;
			uint64_t speed_raw = 0;
			bool selected = false;
			bool observed = false;

			if (name[0] == '.')
				continue;
			if (!sysdevice_is_candidate(name))
				continue;

			for (i = 0; i < bpf_attach_ifname_count; i++) {
				if (!strcmp(bpf_attach_ifnames[i], name)) {
					selected = true;
					break;
				}
			}
			for (i = 0; i < observe_ifname_count; i++) {
				if (!strcmp(observe_ifnames[i], name)) {
					observed = true;
					break;
				}
			}

			snprintf(path, sizeof(path), "/sys/class/net/%s/bridge", name);
			is_bridge = (stat(path, &st) == 0 && S_ISDIR(st.st_mode));

			snprintf(path, sizeof(path), "/sys/class/net/%s/brport", name);
			has_upper = (stat(path, &st) == 0 && S_ISDIR(st.st_mode));

			(void)sysdevice_read_u64(name, "speed", &speed_raw);

			d = json_object_new_object();
			json_object_object_add(d, "name", json_object_new_string(name));
			json_object_object_add(d, "selected", json_object_new_boolean(selected));
			json_object_object_add(d, "observed", json_object_new_boolean(observed));
			json_object_object_add(d, "recommended_lan",
			                       json_object_new_boolean(sysdevice_is_recommended_lan(name)));
			json_object_object_add(d, "is_bridge", json_object_new_boolean(is_bridge));
			json_object_object_add(d, "is_bridge_port", json_object_new_boolean(has_upper));
			/* explicitly flag NSS mirror ifaces so the UI can tell the
			 * user "this is a mirror, don't attach BPF here". */
			json_object_object_add(d, "is_nss_ifb",
			                       json_object_new_boolean(!strcmp(name, "nssifb")));
			if (speed_raw > 0 && speed_raw < (1ULL << 31))
				json_object_object_add(d, "speed_mbps",
				                       json_object_new_int64((int64_t)speed_raw));
			json_object_array_add(devs, d);
		}
		closedir(dir);
	}

	json_object_object_add(root, "devices", devs);
	{
		struct json_object *cur = json_object_new_array();
		for (i = 0; i < bpf_attach_ifname_count; i++)
			json_object_array_add(cur, json_object_new_string(bpf_attach_ifnames[i]));
		json_object_object_add(root, "current_ifnames", cur);
	}
	{
		struct json_object *cur = json_object_new_array();
		for (i = 0; i < observe_ifname_count; i++)
			json_object_array_add(cur, json_object_new_string(observe_ifnames[i]));
		json_object_object_add(root, "current_observed", cur);
	}

	return send_json_reply(ubus, req, root);
}

static int interfaces_method(struct ubus_context *ubus, struct ubus_object *obj,
			     struct ubus_request_data *req, const char *method,
			     struct blob_attr *msg)
{
	struct json_object *root = json_object_new_object();
	struct json_object *interfaces = json_object_new_array();
	size_t i;
	uint64_t now_ms = monotonic_time_ms();
	struct interface_stat_sample {
		char name[IFNAME_STR_LEN];
		uint64_t rx_bytes;
		uint64_t tx_bytes;
		uint64_t snapshot_ms;
		bool valid;
	};
	/* capacity = attach + observe */
	static struct interface_stat_sample previous[2 * LANSPEED_BPF_IFACE_MAX];

	(void)obj;
	(void)method;
	(void)msg;

	for (i = 0; i < bpf_attach_ifname_count + observe_ifname_count; i++) {
		const char *name;
		const char *role;
		char path[PATH_MAX];
		char buf[64];
		FILE *fp;
		uint64_t rx_bytes = 0, tx_bytes = 0;
		uint64_t rx_bps = 0, tx_bps = 0;
		uint64_t delta_ms = 0;
		bool stats_ok = false;
		struct json_object *iface = json_object_new_object();
		struct interface_stat_sample *prev = NULL;
		size_t j;

		if (i < bpf_attach_ifname_count) {
			name = bpf_attach_ifnames[i];
			role = "lan";
		} else {
			name = observe_ifnames[i - bpf_attach_ifname_count];
			role = "observe";
		}

		snprintf(path, sizeof(path), "/sys/class/net/%s/statistics/rx_bytes", name);
		fp = fopen(path, "r");
		if (fp) {
			if (fgets(buf, sizeof(buf), fp))
				rx_bytes = strtoull(buf, NULL, 10);
			fclose(fp);
			stats_ok = true;
		}
		snprintf(path, sizeof(path), "/sys/class/net/%s/statistics/tx_bytes", name);
		fp = fopen(path, "r");
		if (fp) {
			if (fgets(buf, sizeof(buf), fp))
				tx_bytes = strtoull(buf, NULL, 10);
			fclose(fp);
		} else {
			stats_ok = false;
		}

		for (j = 0; j < ARRAY_SIZE(previous); j++) {
			if (previous[j].valid && !strcmp(previous[j].name, name)) {
				prev = &previous[j];
				break;
			}
		}
		if (stats_ok && prev && now_ms > prev->snapshot_ms) {
			delta_ms = now_ms - prev->snapshot_ms;
			if (rx_bytes >= prev->rx_bytes && delta_ms)
				rx_bps = ((rx_bytes - prev->rx_bytes) * 8000ULL) / delta_ms;
			if (tx_bytes >= prev->tx_bytes && delta_ms)
				tx_bps = ((tx_bytes - prev->tx_bytes) * 8000ULL) / delta_ms;
		}
		if (stats_ok) {
			struct interface_stat_sample *slot = prev;
			if (!slot) {
				for (j = 0; j < ARRAY_SIZE(previous); j++) {
					if (!previous[j].valid) { slot = &previous[j]; break; }
				}
			}
			if (slot) {
				snprintf(slot->name, sizeof(slot->name), "%s", name);
				slot->rx_bytes = rx_bytes;
				slot->tx_bytes = tx_bytes;
				slot->snapshot_ms = now_ms;
				slot->valid = true;
			}
		}

		json_object_object_add(iface, "name", json_object_new_string(name));
		json_object_object_add(iface, "role", json_object_new_string(role));
		json_object_object_add(iface, "status",
			json_object_new_string(stats_ok ? "available" : "missing"));
		json_object_object_add(iface, "rx_bytes", json_object_new_int64((int64_t)rx_bytes));
		json_object_object_add(iface, "tx_bytes", json_object_new_int64((int64_t)tx_bytes));
		json_object_object_add(iface, "rx_bps", json_object_new_int64((int64_t)rx_bps));
		json_object_object_add(iface, "tx_bps", json_object_new_int64((int64_t)tx_bps));
		json_object_object_add(iface, "delta_ms", json_object_new_int64((int64_t)delta_ms));
		json_object_object_add(iface, "sample_ms", json_object_new_int64((int64_t)now_ms));
		json_object_object_add(iface, "source",
			json_object_new_string("/sys/class/net/<if>/statistics"));
		json_object_object_add(iface, "coverage",
			json_object_new_string("includes_hardware_offload_and_switch_bridge"));
		json_object_array_add(interfaces, iface);
	}

	json_object_object_add(root, "interfaces", interfaces);
	json_object_object_add(root, "monotonic_ms", json_object_new_int64((int64_t)now_ms));
	json_object_object_add(root, "note",
		json_object_new_string("Per-interface totals from kernel net device counters; reflect hardware-offloaded and hardware-switched traffic too."));

	return send_json_reply(ubus, req, root);
}

static const struct ubus_method lanspeed_methods[] = {
	UBUS_METHOD_NOARG("status", status_method),
	UBUS_METHOD_NOARG("clients", clients_method),
	UBUS_METHOD_NOARG("health", health_method),
	UBUS_METHOD_NOARG("interfaces", interfaces_method),
	UBUS_METHOD_NOARG("sysdevices", sysdevices_method),
};

static struct ubus_object_type lanspeed_object_type =
	UBUS_OBJECT_TYPE("lanspeed", lanspeed_methods);

static struct ubus_object lanspeed_object = {
	.name = "lanspeed",
	.type = &lanspeed_object_type,
	.methods = lanspeed_methods,
	.n_methods = ARRAY_SIZE(lanspeed_methods),
};

static void add_bpf_attach_ifname(const char *name)
{
	size_t i;
	size_t len;

	if (!name || !*name)
		return;
	/* nssifb is the NSS ingress-shaping mirror interface. Attaching a
	 * BPF filter to it would count mirrored ingress bytes, double-billing
	 * the real physical interface. Explicitly reject and let the caller
	 * surface a warning via the caller path. */
	if (!strcmp(name, "nssifb"))
		return;
	if (bpf_attach_ifname_count >= LANSPEED_BPF_IFACE_MAX)
		return;

	len = strlen(name);
	if (len >= LANSPEED_BPF_IFNAME_LEN)
		return;

	for (i = 0; i < bpf_attach_ifname_count; i++) {
		if (!strcmp(bpf_attach_ifnames[i], name))
			return;
	}

	snprintf(bpf_attach_ifnames[bpf_attach_ifname_count],
		 sizeof(bpf_attach_ifnames[0]), "%s", name);
	bpf_attach_ifname_count++;
}

static void add_observe_ifname(const char *name)
{
	size_t i;
	size_t len;

	if (!name || !*name)
		return;
	if (observe_ifname_count >= LANSPEED_BPF_IFACE_MAX)
		return;

	len = strlen(name);
	if (len >= LANSPEED_BPF_IFNAME_LEN)
		return;

	/* skip if already scheduled for BPF attach */
	for (i = 0; i < bpf_attach_ifname_count; i++) {
		if (!strcmp(bpf_attach_ifnames[i], name))
			return;
	}
	for (i = 0; i < observe_ifname_count; i++) {
		if (!strcmp(observe_ifnames[i], name))
			return;
	}

	snprintf(observe_ifnames[observe_ifname_count],
		 sizeof(observe_ifnames[0]), "%s", name);
	observe_ifname_count++;
}

static void load_bpf_attach_list(struct uci_context *uci)
{
	struct uci_ptr ptr;
	struct uci_element *e;
	char ifname_path[] = "lanspeed.main.ifname";
	char include_path[] = "lanspeed.main.interface_include";

	rejected_nssifb_collect = false;

	if (!uci_lookup_ptr(uci, &ptr, ifname_path, true) && ptr.o) {
		if (ptr.o->type == UCI_TYPE_LIST) {
			uci_foreach_element(&ptr.o->v.list, e) {
				if (!strcmp(e->name, "nssifb"))
					rejected_nssifb_collect = true;
				add_bpf_attach_ifname(e->name);
			}
		} else if (ptr.o->type == UCI_TYPE_STRING && ptr.o->v.string) {
			if (!strcmp(ptr.o->v.string, "nssifb"))
				rejected_nssifb_collect = true;
			add_bpf_attach_ifname(ptr.o->v.string);
		}
	}
	if (!uci_lookup_ptr(uci, &ptr, include_path, true) && ptr.o) {
		if (ptr.o->type == UCI_TYPE_LIST) {
			uci_foreach_element(&ptr.o->v.list, e) {
				if (!strcmp(e->name, "nssifb"))
					rejected_nssifb_collect = true;
				add_bpf_attach_ifname(e->name);
			}
		} else if (ptr.o->type == UCI_TYPE_STRING && ptr.o->v.string) {
			if (!strcmp(ptr.o->v.string, "nssifb"))
				rejected_nssifb_collect = true;
			add_bpf_attach_ifname(ptr.o->v.string);
		}
	}
}

static void load_observe_list(struct uci_context *uci)
{
	struct uci_ptr ptr;
	struct uci_element *e;
	char observe_path[] = "lanspeed.main.observe";

	if (!uci_lookup_ptr(uci, &ptr, observe_path, true) && ptr.o) {
		if (ptr.o->type == UCI_TYPE_LIST) {
			uci_foreach_element(&ptr.o->v.list, e) {
				add_observe_ifname(e->name);
			}
		} else if (ptr.o->type == UCI_TYPE_STRING && ptr.o->v.string) {
			add_observe_ifname(ptr.o->v.string);
		}
	}
}

static void load_config(void)
{
	struct uci_context *uci = uci_alloc_context();
	struct uci_ptr ptr;
	char value[32];
	char refresh_path[] = "lanspeed.main.refresh_interval_ms";
	char max_clients_path[] = "lanspeed.main.max_clients";
	char bpf_path[] = "lanspeed.main.enable_bpf";
	char fallback_path[] = "lanspeed.main.enable_conntrack_fallback";

	if (!uci)
		return;

	if (!uci_lookup_ptr(uci, &ptr, refresh_path, true) && ptr.o && ptr.o->v.string) {
		int parsed = atoi(ptr.o->v.string);

		if (parsed >= MIN_REFRESH_INTERVAL_MS)
			refresh_interval_ms = parsed;
		else if (parsed > 0) {
			refresh_interval_ms = MIN_REFRESH_INTERVAL_MS;
			refresh_interval_clamped = true;
		}
	}

	if (!uci_lookup_ptr(uci, &ptr, max_clients_path, true) && ptr.o && ptr.o->v.string) {
		int parsed = atoi(ptr.o->v.string);

		if (parsed >= 0)
			max_clients = parsed;
	}

	if (!uci_lookup_ptr(uci, &ptr, bpf_path, true) && ptr.o && ptr.o->v.string) {
		strncpy(value, ptr.o->v.string, sizeof(value) - 1);
		value[sizeof(value) - 1] = '\0';
		enable_bpf = !strcmp(value, "1") || !strcmp(value, "true");
	}

	if (!uci_lookup_ptr(uci, &ptr, fallback_path, true) && ptr.o && ptr.o->v.string) {
		strncpy(value, ptr.o->v.string, sizeof(value) - 1);
		value[sizeof(value) - 1] = '\0';
		enable_conntrack_fallback = !strcmp(value, "1") || !strcmp(value, "true");
	}

	load_bpf_attach_list(uci);
	load_observe_list(uci);

	uci_free_context(uci);
}

static void start_bpf_runtime(void)
{
	const char *env_path;
	const char *object_path;
	size_t i;
	int attached_ok = 0;

	if (!enable_bpf)
		return;

	env_path = getenv("LANSPEED_BPF_OBJECT_PATH");
	object_path = (env_path && *env_path) ? env_path : LANSPEED_BPF_OBJECT_PATH;
	snprintf(bpf_object_runtime_path, sizeof(bpf_object_runtime_path),
		 "%s", object_path);

	if (!lanspeed_bpf_init(object_path))
		return;

	for (i = 0; i < bpf_attach_ifname_count; i++) {
		if (lanspeed_bpf_attach_iface(bpf_attach_ifnames[i]) == 0)
			attached_ok++;
	}

	if (attached_ok == 0) {
		lanspeed_bpf_shutdown();
		return;
	}

	bpf_runtime_enabled = true;
	bpf_collect_timer.cb = bpf_collect_tick;
	uloop_timeout_set(&bpf_collect_timer,
			  refresh_interval_ms > 0 ? refresh_interval_ms :
						    DEFAULT_REFRESH_INTERVAL_MS);
}

static void stop_bpf_runtime(void)
{
	if (bpf_collect_timer.cb)
		uloop_timeout_cancel(&bpf_collect_timer);
	lanspeed_bpf_shutdown();
	bpf_runtime_enabled = false;
}

static void handle_signal(int signo)
{
	(void)signo;
	uloop_end();
}

int main(void)
{
	int ret;

	load_config();
	signal(SIGINT, handle_signal);
	signal(SIGTERM, handle_signal);

	uloop_init();
	ctx = ubus_connect(NULL);
	if (!ctx) {
		uloop_done();
		return EXIT_FAILURE;
	}

	ubus_add_uloop(ctx);
	ret = ubus_add_object(ctx, &lanspeed_object);
	if (ret) {
		ubus_free(ctx);
		uloop_done();
		return EXIT_FAILURE;
	}

	start_bpf_runtime();

	uloop_run();
	stop_bpf_runtime();
	ubus_free(ctx);
	uloop_done();
	blob_buf_free(&reply);

	return EXIT_SUCCESS;
}
