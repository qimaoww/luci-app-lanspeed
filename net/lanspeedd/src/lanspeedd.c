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
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <json-c/json.h>
#include <libubox/blobmsg_json.h>
#include <libubox/utils.h>
#include <libubox/uloop.h>
#include <libubus.h>
#include <uci.h>

#include "lanspeed_bpf.h"
#include "lanspeed_bpf_collector.h"
#include "lanspeed_config.h"
#include "lanspeed_conntrack.h"
#include "lanspeed_history.h"
#include "lanspeed_identity.h"
#include "lanspeed_nss.h"

#define LANSPEED_VERSION "0.1.5"
#ifndef LANSPEED_RELEASE
#define LANSPEED_RELEASE "2"
#endif
#define LANSPEED_FULL_VERSION LANSPEED_VERSION "-r" LANSPEED_RELEASE
#define RATE_WINDOW_COUNT 3
#define STALE_CLIENT_MS 5000
#define COMMAND_OUTPUT_LIMIT 4096
#define LANSPEED_BPF_PACKAGE_MARKER "/usr/share/lanspeed/bpf/collector-model.json"
#define LANSPEED_BPF_OBJECT_PATH "/usr/lib/bpf/lanspeed_tc.o"
#define LANSPEED_BPF_SOURCE "lanspeed_tc.bpf.c"
#define LANSPEED_TC_FILTER_PREF 49152
#define LANSPEED_TC_FILTER_HANDLE "0x1eed"
#define LANSPEED_TC_FILTER_EARLY_PREF 1
#define LANSPEED_TC_FILTER_EARLY_HANDLE "0x1eee"
#define LANSPEED_TC_FILTER_OWNER "lanspeed"
#define DAE_FWMARK "0x8000000"
#define DAE_ROUTE_TABLE "2023"
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
static uint64_t active_client_window_ms = DEFAULT_ACTIVE_CLIENT_WINDOW_MS;
static uint64_t active_client_min_bps = DEFAULT_ACTIVE_CLIENT_MIN_BPS;
static int overview_window_samples = DEFAULT_OVERVIEW_WINDOW_SAMPLES;
static bool enable_bpf;
static bool enable_conntrack_fallback = true;
static bool refresh_interval_clamped;
static bool active_client_window_clamped;
static bool active_client_min_bps_clamped;
static bool overview_window_samples_clamped;
static bool rejected_nssifb_collect;

static enum collector_mode_setting rate_collector_mode = COLLECTOR_MODE_AUTO;
static enum collector_mode_setting conn_collector_mode = COLLECTOR_MODE_AUTO;

struct runtime_probe;
static bool nss_ecm_direct_preferred(const struct runtime_probe *probe);
static bool nss_ecm_direct_overlay_enabled(const struct runtime_probe *probe);
static bool nss_conntrack_sync_preferred(const struct runtime_probe *probe);
static bool nss_conntrack_sync_fallback_available(const struct runtime_probe *probe);
static bool nss_conntrack_sync_stable_active(const struct runtime_probe *probe);
static bool nss_conntrack_sync_reader_available(const struct runtime_probe *probe);
static bool daed_runtime_active(const struct runtime_probe *probe);
static bool nss_daed_should_prefer_bpf(const struct runtime_probe *probe);
static bool nss_daed_nss_fallback_active(const struct runtime_probe *probe);
static void add_conntrack_fallback_runtime_warnings(struct runtime_probe *probe);
static void add_nss_ecm_direct_runtime_warnings(struct runtime_probe *probe);
static void add_conflicts_from_probe(struct runtime_probe *probe);
static void inspect_bpf_assets(struct runtime_probe *probe);
static void inspect_files_direct(struct runtime_probe *probe);
static void inspect_nss(struct runtime_probe *probe);
static void inspect_collector_attach_model(struct runtime_probe *probe);
static const char *rate_collector_mode_config_name(void)
{
	return collector_mode_name(rate_collector_mode);
}

static const char *conn_collector_mode_config_name(void)
{
	return collector_mode_name(conn_collector_mode);
}

static const char *collector_mode_config_name(void)
{
	/* Legacy API field: before 0.1.1-r5 this single value controlled
	 * both rate and connection-count collection. Keep it as the rate
	 * mode so old consumers still learn the live-speed policy. */
	return rate_collector_mode_config_name();
}

static bool conn_collector_mode_is_forced(void)
{
	return conn_collector_mode == COLLECTOR_MODE_CONNTRACK_NETLINK ||
	       conn_collector_mode == COLLECTOR_MODE_CONNTRACK_PROCFS;
}

static bool rate_collector_mode_allows_bpf(void)
{
	return rate_collector_mode == COLLECTOR_MODE_AUTO ||
	       rate_collector_mode == COLLECTOR_MODE_BPF;
}

static bool rate_collector_mode_forces_bpf(void)
{
	return rate_collector_mode == COLLECTOR_MODE_BPF;
}

static bool rate_collector_mode_forces_nss_ecm_direct(void)
{
	return rate_collector_mode == COLLECTOR_MODE_NSS_ECM_DIRECT;
}

static bool rate_collector_mode_forces_nss_conntrack_sync(void)
{
	return rate_collector_mode == COLLECTOR_MODE_NSS_CONNTRACK_SYNC;
}

static bool rate_collector_mode_allows_conntrack_sync(void)
{
	return rate_collector_mode == COLLECTOR_MODE_AUTO ||
	       rate_collector_mode == COLLECTOR_MODE_NSS_ECM_DIRECT ||
	       rate_collector_mode == COLLECTOR_MODE_NSS_CONNTRACK_SYNC;
}

static const char *conntrack_stats_source(const struct conntrack_collect_stats *stats)
{
	if (stats && stats->netlink_read)
		return CONNTRACK_NETLINK_SOURCE;
	if (stats && stats->procfs_read)
		return CONNTRACK_PROCFS_SOURCE;
	return conn_collector_mode_config_name();
}

static const char *conntrack_stats_runtime_source(const struct conntrack_collect_stats *stats)
{
	if (stats && stats->netlink_read)
		return "lanspeedd_ctnetlink_conntrack_acct";
	return "lanspeedd_procfs_conntrack_acct";
}

static const char *conntrack_stats_counter_source(const struct conntrack_collect_stats *stats)
{
	if (stats && stats->netlink_read)
		return "ctnetlink_conntrack_acct_orig_reply_bytes";
	return "procfs_conntrack_acct_orig_reply_bytes";
}

static const char *conntrack_stats_collector_mode(const struct runtime_probe *probe,
						  const struct conntrack_collect_stats *stats)
{
	if (probe && nss_conntrack_sync_reader_available(probe))
		return "conntrack_ecm_sync";
	if (stats && stats->netlink_read)
		return CONNTRACK_NETLINK_SOURCE;
	if (stats && stats->procfs_read)
		return CONNTRACK_PROCFS_SOURCE;
	return CONNTRACK_LEGACY_SOURCE;
}

static struct conntrack_client_sample previous_conntrack_samples[DEFAULT_MAX_CLIENTS];
static size_t previous_conntrack_sample_count;
static uint64_t previous_conntrack_snapshot_ms;
static bool previous_conntrack_snapshot_valid;

static struct conntrack_client_sample previous_nss_ecm_direct_samples[DEFAULT_MAX_CLIENTS];
static size_t previous_nss_ecm_direct_sample_count;
static uint64_t previous_nss_ecm_direct_snapshot_ms;
static bool previous_nss_ecm_direct_snapshot_valid;

#define LANSPEED_BPF_IFACE_MAX 16
#define LANSPEED_BPF_IFNAME_LEN IFNAME_STR_LEN

static char bpf_attach_ifnames[LANSPEED_BPF_IFACE_MAX][LANSPEED_BPF_IFNAME_LEN];
static size_t bpf_attach_ifname_count;
static char bpf_object_runtime_path[PATH_MAX];

/* observe-only ifnames: shown in interfaces throughput card but not BPF-attached */
static char observe_ifnames[LANSPEED_BPF_IFACE_MAX][LANSPEED_BPF_IFNAME_LEN];
static size_t observe_ifname_count;

static struct bpf_snapshot_cache bpf_cache;

static struct lanspeed_coverage_ring coverage_ring;
static struct lanspeed_overview_ring overview_ring;

static struct uloop_timeout bpf_collect_timer;
static bool bpf_runtime_enabled;
static bool bpf_runtime_early_passthrough;
static uint64_t bpf_runtime_self_heal_failures;
static char bpf_runtime_last_self_heal_failure[128];

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
	bool nss_ecm_direct_state;
	bool nss_ecm_direct_supported;
	int  nss_ecm_direct_state_errno;
	unsigned int nss_ecm_direct_state_major;
	char nss_ecm_direct_state_source[PATH_MAX];
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
	bool dae_running;
	bool daed_running;
	bool dae_process;
	bool daed_process;
	bool dae_iface;
	bool dae_peer_iface;
	bool dae_tc_filters;
	bool dae_preempts_bpf_ingress;
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

static struct runtime_probe cached_runtime_probe;
static bool cached_runtime_probe_valid;

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

static bool service_output_has_running_instance(const char *output)
{
	return output && (strstr(output, "\"running\": true") != NULL ||
			  strstr(output, "\"running\":true") != NULL);
}

static bool process_running(const char *name)
{
	char command[96];
	char output[COMMAND_OUTPUT_LIMIT];

	if (!name || !name[0])
		return false;

	snprintf(command, sizeof(command), "pidof %s 2>/dev/null", name);
	return run_command_capture(command, output, sizeof(output)) == 0 && output[0] != '\0';
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

static bool line_contains_lanspeed_filter_conflict(const char *line)
{
	bool default_conflict;
	bool early_conflict;

	if (!line || strstr(line, LANSPEED_TC_FILTER_OWNER) != NULL)
		return false;

	default_conflict = strstr(line, "pref 49152") != NULL &&
			   (strstr(line, "handle 0x1eed") != NULL ||
			    strstr(line, "handle 1eed") != NULL);
	early_conflict = strstr(line, "pref 1") != NULL &&
			 (strstr(line, "handle 0x1eee") != NULL ||
			  strstr(line, "handle 1eee") != NULL);

	return default_conflict || early_conflict;
}

static bool ifname_is_bpf_attach_ifname(const char *ifname)
{
	size_t i;

	if (!ifname || !ifname[0])
		return false;

	for (i = 0; i < bpf_attach_ifname_count; i++) {
		if (!strcmp(bpf_attach_ifnames[i], ifname))
			return true;
	}

	return false;
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
			if (ifname_is_bpf_attach_ifname(ifname) &&
			    direction && !strcmp(direction, "ingress") &&
			    atoi(pref) > 0 && atoi(pref) < LANSPEED_TC_FILTER_PREF)
				probe->dae_preempts_bpf_ingress = true;
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

static void runtime_probe_copy_cached_scalars(struct runtime_probe *dst,
					     const struct runtime_probe *src)
{
	struct json_object *warnings = dst->warnings;
	struct json_object *conflicts = dst->conflicts;
	struct json_object *evidence = dst->evidence;
	struct json_object *tc_filters = dst->tc_filters;
	struct json_object *commands = dst->commands;
	struct json_object *files = dst->files;
	struct json_object *uci = dst->uci;
	struct json_object *ubus_evidence = dst->ubus_evidence;
	struct json_object *source_commands = dst->source_commands;
	struct json_object *source_files = dst->source_files;
	struct json_object *source_uci = dst->source_uci;
	struct json_object *source_ubus = dst->source_ubus;

	*dst = *src;
	dst->warnings = warnings;
	dst->conflicts = conflicts;
	dst->evidence = evidence;
	dst->tc_filters = tc_filters;
	dst->commands = commands;
	dst->files = files;
	dst->uci = uci;
	dst->ubus_evidence = ubus_evidence;
	dst->source_commands = source_commands;
	dst->source_files = source_files;
	dst->source_uci = source_uci;
	dst->source_ubus = source_ubus;
}

static void runtime_probe_cache_store(const struct runtime_probe *probe)
{
	if (!probe)
		return;
	runtime_probe_copy_cached_scalars(&cached_runtime_probe, probe);
	cached_runtime_probe_valid = true;
}

static void apply_runtime_probe_common_warnings(struct runtime_probe *probe)
{
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
		add_warning(probe, "nssifb_detected");
	if (rejected_nssifb_collect)
		add_warning(probe, "nssifb_collect_rejected");
	if (probe->fullcone) {
		add_warning(probe, "fullcone_detected");
		add_warning(probe, "fullcone_nat_enabled");
	}
	if (refresh_interval_clamped)
		add_warning(probe, "refresh_interval_below_minimum");
	if (active_client_window_clamped)
		add_warning(probe, "active_client_window_below_minimum");
	if (active_client_min_bps_clamped)
		add_warning(probe, "active_client_min_bps_below_minimum");
	if (overview_window_samples_clamped)
		add_warning(probe, "overview_window_samples_out_of_range");
	add_nss_ecm_direct_runtime_warnings(probe);
	add_conntrack_fallback_runtime_warnings(probe);
	add_conflicts_from_probe(probe);
}

static void load_cached_runtime_probe(struct runtime_probe *probe)
{
	if (cached_runtime_probe_valid)
		runtime_probe_copy_cached_scalars(probe, &cached_runtime_probe);
	else
		inspect_command_capabilities(probe);

	inspect_files_direct(probe);
	inspect_bpf_assets(probe);
	inspect_nss(probe);
	inspect_collector_attach_model(probe);
	apply_runtime_probe_common_warnings(probe);
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
		probe->dae_running = probe->dae_service && service_output_has_running_instance(output);
		add_ubus_evidence(probe, "service_dae", "service.dae", true, exit_code,
				  probe->dae_running ? "dae service running" :
				  (probe->dae_service ? "dae service present without running instance" : "dae service not present"));

		exit_code = run_command_capture("ubus call service list '{\"name\":\"daed\"}' 2>&1", output, sizeof(output));
		probe->daed_service = exit_code == 0 && strstr(output, "daed") != NULL;
		probe->daed_running = probe->daed_service && service_output_has_running_instance(output);
		add_ubus_evidence(probe, "service_daed", "service.daed", true, exit_code,
				  probe->daed_running ? "daed service running" :
				  (probe->daed_service ? "daed service present without running instance" : "daed service not present"));
	} else {
		add_ubus_evidence(probe, "service_dae", "service.dae", false, -1, "ubus command missing");
		add_ubus_evidence(probe, "service_daed", "service.daed", false, -1, "ubus command missing");
	}

	probe->dae_process = process_running("dae");
	probe->daed_process = process_running("daed");

	if (probe->dae_service || probe->daed_service ||
	    probe->dae_running || probe->daed_running ||
	    probe->dae_process || probe->daed_process)
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
	if (probe->dae_preempts_bpf_ingress)
		add_warning(probe, "dae_tc_preempts_bpf_ingress");
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

	if (!enable_bpf || !rate_collector_mode_allows_bpf() || !bpf_runtime_enabled)
		return false;
	if (probe && !probe->safe_attach)
		return false;

	freshness = (uint64_t)refresh_interval_ms * 3ULL;
	if (freshness == 0)
		freshness = (uint64_t)DEFAULT_REFRESH_INTERVAL_MS * 3ULL;
	return lanspeed_bpf_runtime_ok(freshness);
}

static bool dae_tc_preempts_bpf_ingress(const struct runtime_probe *probe);

static struct lanspeed_overview_config overview_config(void)
{
	struct lanspeed_overview_config config = {
		.overview_window_samples = overview_window_samples,
		.active_client_window_ms = active_client_window_ms,
		.active_client_min_bps = active_client_min_bps
	};

	return config;
}

static void bpf_runtime_reset_rate_state(void)
{
	bpf_snapshot_cache_reset(&bpf_cache);
	lanspeed_coverage_reset(&coverage_ring);
}

static bool bpf_runtime_recover_if_needed(const char *reason)
{
	size_t i;
	bool attempted = false;
	bool ok = true;

	if (!enable_bpf || !rate_collector_mode_allows_bpf() || !bpf_runtime_enabled)
		return true;

	for (i = 0; i < bpf_attach_ifname_count; i++) {
		int ret;

		ret = lanspeed_bpf_ensure_attached(
			bpf_attach_ifnames[i], bpf_runtime_early_passthrough,
			reason);
		if (ret != 0)
			attempted = true;
		if (ret < 0)
			ok = false;
	}

	if (!ok) {
		const struct lanspeed_bpf_status *status = lanspeed_bpf_get_status();
		const char *failure = status && status->error[0] ?
			status->error : "bpf_tc_self_heal_failed";

		bpf_runtime_self_heal_failures++;
		snprintf(bpf_runtime_last_self_heal_failure,
			 sizeof(bpf_runtime_last_self_heal_failure),
			 "%.*s",
			 (int)(sizeof(bpf_runtime_last_self_heal_failure) - 1),
			 failure);
		return false;
	}

	if (attempted)
		bpf_runtime_reset_rate_state();

	return true;
}

static bool bpf_runtime_refresh_attach_policy(struct runtime_probe *probe)
{
	size_t i;
	bool want_early;
	bool changed = false;
	bool ok = true;

	if (!enable_bpf || !rate_collector_mode_allows_bpf() || !bpf_runtime_enabled || !probe)
		return false;

	want_early = dae_tc_preempts_bpf_ingress(probe);
	if (want_early == bpf_runtime_early_passthrough)
		return false;

	for (i = 0; i < bpf_attach_ifname_count; i++) {
		if (lanspeed_bpf_attach_iface_mode(bpf_attach_ifnames[i], want_early) != 0) {
			ok = false;
			break;
		}
	}

	if (ok) {
		for (i = 0; i < bpf_attach_ifname_count; i++)
			(void)lanspeed_bpf_detach_iface_mode(
				bpf_attach_ifnames[i], bpf_runtime_early_passthrough);
		bpf_runtime_early_passthrough = want_early;
		changed = true;
		bpf_runtime_reset_rate_state();
	} else {
		const struct lanspeed_bpf_status *status = lanspeed_bpf_get_status();
		const char *failure = status && status->error[0] ?
			status->error : "bpf_tc_policy_switch_failed";

		for (i = 0; i < bpf_attach_ifname_count; i++)
			(void)lanspeed_bpf_detach_iface_mode(bpf_attach_ifnames[i],
							     want_early);
		bpf_runtime_self_heal_failures++;
		snprintf(bpf_runtime_last_self_heal_failure,
			 sizeof(bpf_runtime_last_self_heal_failure),
			 "%.*s",
			 (int)(sizeof(bpf_runtime_last_self_heal_failure) - 1),
			 failure);
	}

	if (changed)
		(void)bpf_runtime_recover_if_needed(
			want_early ? "dae_tc_preempt_policy_switch" :
				     "dae_tc_preempt_policy_restore");

	return changed;
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
	if (bpf_runtime_self_heal_failures > 0)
		add_warning(probe, "bpf_tc_self_heal_failed");
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

static void inspect_files_common(struct runtime_probe *probe, bool refresh_flowtable_command)
{
	char value[64];
	bool present;
	bool proc_present;
	bool debug_present;

	present = read_file_trimmed("/proc/sys/net/netfilter/nf_conntrack_acct", value, sizeof(value));
	probe->nf_conntrack_acct_present = present;
	probe->nf_conntrack_acct = present && !strcmp(value, "1");
	add_file_evidence(probe, "nf_conntrack_acct", "/proc/sys/net/netfilter/nf_conntrack_acct", present, present ? value : NULL);
	if (present && !probe->nf_conntrack_acct) {
		add_warning(probe, "nf_conntrack_acct_disabled");
		add_warning(probe, "conntrack_acct_disabled");
	}

	proc_present = file_exists("/proc/net/nf_flowtable");
	debug_present = file_exists("/sys/kernel/debug/netfilter/nf_flowtable");
	if (refresh_flowtable_command) {
		inspect_flowtable_counter(probe);
	} else {
		add_file_evidence(probe, "flowtable_proc", "/proc/net/nf_flowtable", proc_present, NULL);
		add_file_evidence(probe, "flowtable_debug", "/sys/kernel/debug/netfilter/nf_flowtable", debug_present, NULL);
		probe->flowtable_counter = probe->flowtable_counter || proc_present || debug_present;
		if (!probe->flowtable_counter)
			add_warning(probe, "flowtable_counter_missing");
	}

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

static void inspect_files_direct(struct runtime_probe *probe)
{
	inspect_files_common(probe, false);
}

static void inspect_files(struct runtime_probe *probe)
{
	inspect_files_common(probe, true);
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
	 * per-flow byte counters back into conntrack, at NSS sync cadence
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
	probe->nss_ecm_direct_state =
		file_exists(NSS_ECM_STATE_DEV_MAJOR_PATH) ||
		file_exists(NSS_ECM_STATE_DEV_PATH);
	probe->nss_ecm_direct_supported = false;
	probe->nss_ecm_direct_state_errno = 0;
	probe->nss_ecm_direct_state_major = 0;
	probe->nss_ecm_direct_state_source[0] = '\0';
	if (probe->nss_ecm_active && probe->nss_ecm_direct_state) {
		FILE *state_file = NULL;

		if (nss_ecm_state_open(&state_file, probe->nss_ecm_direct_state_source,
				       sizeof(probe->nss_ecm_direct_state_source),
				       &probe->nss_ecm_direct_state_errno,
				       &probe->nss_ecm_direct_state_major)) {
			probe->nss_ecm_direct_supported = true;
			fclose(state_file);
		}
	}

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

static bool nss_conntrack_sync_preferred(const struct runtime_probe *probe)
{
	if (rate_collector_mode_forces_bpf())
		return false;
	return rate_collector_mode_allows_conntrack_sync() &&
	       nss_conntrack_sync_fallback_available(probe) &&
	       (rate_collector_mode_forces_nss_conntrack_sync() ||
	        rate_collector_mode_forces_nss_ecm_direct() ||
	        !nss_daed_should_prefer_bpf(probe));
}

static bool nss_conntrack_sync_fallback_available(const struct runtime_probe *probe)
{
	if (rate_collector_mode_forces_bpf())
		return false;
	return conntrack_fallback_accounting_safe(probe) &&
	       probe->nss_present &&
	       (probe->nss_ecm_active || probe->nss_ppe_active) &&
	       !nss_daed_should_prefer_bpf(probe);
}

static bool nss_conntrack_sync_reader_available(const struct runtime_probe *probe)
{
	if (nss_conntrack_sync_preferred(probe))
		return true;
	return nss_conntrack_sync_fallback_available(probe) &&
	       rate_collector_mode_forces_nss_ecm_direct();
}

static bool nss_ecm_direct_supported(const struct runtime_probe *probe)
{
	return probe &&
	       !rate_collector_mode_forces_bpf() &&
	       !rate_collector_mode_forces_nss_conntrack_sync() &&
	       probe->nss_present &&
	       probe->nss_ecm_active &&
	       probe->nss_ecm_direct_supported;
}

static bool nss_ecm_direct_preferred(const struct runtime_probe *probe)
{
	return nss_ecm_direct_supported(probe) &&
	       rate_collector_mode_forces_nss_ecm_direct();
}

static bool nss_ecm_direct_overlay_enabled(const struct runtime_probe *probe)
{
	return nss_ecm_direct_supported(probe) &&
	       (rate_collector_mode == COLLECTOR_MODE_AUTO ||
	        rate_collector_mode_forces_nss_ecm_direct()) &&
	       !nss_daed_should_prefer_bpf(probe);
}

static bool nss_conntrack_sync_stable_active(const struct runtime_probe *probe)
{
	return nss_conntrack_sync_preferred(probe) ||
	       (nss_ecm_direct_overlay_enabled(probe) &&
	        nss_conntrack_sync_reader_available(probe));
}

static bool dae_tc_preempts_bpf_ingress(const struct runtime_probe *probe)
{
	return probe && probe->dae_preempts_bpf_ingress;
}

static bool daed_runtime_active(const struct runtime_probe *probe)
{
	return probe && (probe->dae_running || probe->daed_running ||
			 probe->dae_process || probe->daed_process);
}

static bool nss_daed_should_prefer_bpf(const struct runtime_probe *probe)
{
	return rate_collector_mode == COLLECTOR_MODE_AUTO &&
	       probe && probe->nss_present && daed_runtime_active(probe) &&
	       bpf_full_available(probe);
}

static bool nss_daed_nss_fallback_active(const struct runtime_probe *probe)
{
	return probe && probe->nss_present && daed_runtime_active(probe) &&
	       !bpf_full_available(probe) &&
	       rate_collector_mode_allows_conntrack_sync() &&
	       (probe->nss_ecm_active || probe->nss_ppe_active);
}

static bool conntrack_primary_preferred(const struct runtime_probe *probe)
{
	return nss_conntrack_sync_stable_active(probe) ||
	       nss_ecm_direct_preferred(probe);
}

static bool bpf_primary_active(const struct runtime_probe *probe)
{
	return rate_collector_mode_allows_bpf() &&
	       bpf_full_available(probe) &&
	       !conntrack_primary_preferred(probe);
}

static bool conntrack_fallback_active(const struct runtime_probe *probe)
{
	return (enable_conntrack_fallback || conn_collector_mode_is_forced()) &&
	       conntrack_primary_preferred(probe) &&
	       conntrack_fallback_accounting_safe(probe);
}

static bool conntrack_clients_read_active(const struct runtime_probe *probe)
{
	if (conntrack_fallback_active(probe))
		return true;
	if (nss_ecm_direct_overlay_enabled(probe))
		return (enable_conntrack_fallback || conn_collector_mode_is_forced()) &&
		       nss_conntrack_sync_reader_available(probe);
	return false;
}

static const char *collector_primary_source(const struct runtime_probe *probe)
{
	if (nss_daed_should_prefer_bpf(probe))
		return "bpf";
	if (nss_conntrack_sync_stable_active(probe))
		return "nss_conntrack_sync";
	if (nss_ecm_direct_preferred(probe))
		return NSS_ECM_DIRECT_SOURCE;
	if (bpf_primary_active(probe))
		return "bpf";
	if (conntrack_fallback_active(probe))
		return "conntrack";
	return "unsupported";
}

static bool conntrack_fallback_low_confidence(const struct runtime_probe *probe)
{
	/* NSS syncs per-flow byte counters (incl. hw-offloaded
	 * routed and bridged flows) back into conntrack at ~1-2 s cadence.
	 * In that scenario hardware_flow_offload=true is not a confidence
	 * killer because conntrack_acct data is still accurate, just
	 * secondly. */
	bool nss_ecm_sync = nss_conntrack_sync_stable_active(probe);
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

static bool conntrack_clients_read_low_confidence(const struct runtime_probe *probe)
{
	bool nss_ecm_sync = nss_conntrack_sync_reader_available(probe);
	bool hw_off_non_nss = probe->hardware_flow_offload && !nss_ecm_sync;

	return conntrack_clients_read_active(probe) &&
	       (!probe->flowtable_counter || probe->software_flow_offload ||
		hw_off_non_nss || probe->openclash_fake_ip ||
		probe->openclash_tun_mix || probe->openclash_router_self_proxy ||
		probe->openclash_udp_proxy || probe->dae || probe->homeproxy ||
		probe->sqm || probe->qosify || probe->ifb ||
		probe->nlbwmon || probe->probe_error || probe->lan_probe_error);
}

static const char *conntrack_clients_read_confidence(const struct runtime_probe *probe)
{
	if (!conntrack_clients_read_active(probe))
		return "unsupported";
	if (conntrack_clients_read_low_confidence(probe))
		return "low";
	return "medium";
}

static void add_conntrack_fallback_runtime_warnings(struct runtime_probe *probe)
{
	if (!conntrack_fallback_active(probe))
		return;

	/* With NSS ECM active, the counter sync covers bridged flows
	 * too, so the "routed / NAT only" disclaimer does not apply. */
	if (nss_conntrack_sync_stable_active(probe)) {
		add_warning(probe, "nss_ecm_sync_cadence");
		if (bpf_full_available(probe))
			add_warning(probe, "nss_prefers_conntrack_sync");
	} else {
		add_warning(probe, "conntrack_routed_nat_only");
	}

	if (!probe->flowtable_counter)
		add_warning(probe, "flowtable_counter_missing");
	if (probe->nlbwmon)
		add_warning(probe, "nlbwmon_counter_conflict");
	if (nss_daed_nss_fallback_active(probe))
		add_warning(probe, "nss_daed_nss_fallback_may_be_inaccurate");
}

static void add_nss_ecm_direct_runtime_warnings(struct runtime_probe *probe)
{
	if (!nss_ecm_direct_overlay_enabled(probe))
		return;

	add_warning(probe, "nss_ecm_direct_active");
	if (nss_daed_nss_fallback_active(probe))
		add_warning(probe, "nss_daed_nss_fallback_may_be_inaccurate");
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

	json_object_object_add(probe->evidence, "collector_mode",
			       json_object_new_string(collector_mode_config_name()));
	json_object_object_add(probe->evidence, "rate_collector_mode",
			       json_object_new_string(rate_collector_mode_config_name()));
	json_object_object_add(probe->evidence, "conn_collector_mode",
			       json_object_new_string(conn_collector_mode_config_name()));
	json_object_object_add(probe->evidence, "effective_collector",
			       json_object_new_string(collector_primary_source(probe)));
	json_object_object_add(collector, "source", json_object_new_string("lanspeedd_tc_bpf_collector"));
	json_object_object_add(collector, "runtime_safe", json_object_new_boolean(true));
	json_object_object_add(collector, "configured_mode", json_object_new_string(collector_mode_config_name()));
	json_object_object_add(collector, "configured_rate_mode", json_object_new_string(rate_collector_mode_config_name()));
	json_object_object_add(collector, "configured_conn_mode", json_object_new_string(conn_collector_mode_config_name()));
	json_object_object_add(collector, "enabled", json_object_new_boolean(enable_bpf && rate_collector_mode_allows_bpf()));
	json_object_object_add(collector, "bpf_source", json_object_new_string(LANSPEED_BPF_SOURCE));
	json_object_object_add(collector, "runtime_object", json_object_new_string(LANSPEED_BPF_OBJECT_PATH));
	json_object_object_add(collector, "optional_package_present", json_object_new_boolean(probe->bpf_package));
	json_object_object_add(collector, "bpf_object_present", json_object_new_boolean(probe->bpf_object));
	json_object_object_add(collector, "safe_attach", json_object_new_boolean(probe->safe_attach));
	json_object_object_add(collector, "bpf_assets_are_evidence_only", json_object_new_boolean(true));
	json_object_object_add(collector, "runtime_attach_map_read_success", json_object_new_boolean(probe->bpf_runtime_metrics));
	json_object_object_add(collector, "live_metrics", json_object_new_boolean(bpf_primary_active(probe)));
	json_object_object_add(collector, "primary_source", json_object_new_string(collector_primary_source(probe)));
	json_object_object_add(collector, "runtime_gate_warning",
			       json_object_new_string(probe->bpf_runtime_metrics ? "" :
						      "bpf_runtime_loader_unavailable"));
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
	json_object_object_add(tc_filter, "self_heal_reorders_existing", json_object_new_boolean(false));
	json_object_object_add(tc_filter, "owner", json_object_new_string(LANSPEED_TC_FILTER_OWNER));
	json_object_object_add(tc_filter, "pref", json_object_new_int(LANSPEED_TC_FILTER_PREF));
	json_object_object_add(tc_filter, "handle", json_object_new_string(LANSPEED_TC_FILTER_HANDLE));
	json_object_object_add(tc_filter, "early_pref", json_object_new_int(LANSPEED_TC_FILTER_EARLY_PREF));
	json_object_object_add(tc_filter, "early_handle", json_object_new_string(LANSPEED_TC_FILTER_EARLY_HANDLE));
	json_object_object_add(tc_filter, "early_passthrough_action", json_object_new_string("TC_ACT_UNSPEC"));
	json_object_object_add(tc_filter, "existing_filters_detected", json_object_new_boolean(probe->existing_tc_filters));
	json_object_object_add(tc_filter, "existing_filters", json_object_get(probe->tc_filters));
	json_object_object_add(tc_filter, "conflict", json_object_new_boolean(probe->tc_filter_conflict));
	json_object_object_add(tc_filter, "conflict_warning", json_object_new_string("tc_filter_conflict"));
	json_object_object_add(tc_filter, "dae_preempts_bpf_ingress",
			       json_object_new_boolean(dae_tc_preempts_bpf_ingress(probe)));
	json_object_object_add(tc_filter, "preempt_warning",
			       json_object_new_string("dae_tc_preempts_bpf_ingress"));
	{
		struct json_object *self_heal = json_object_new_object();
		const struct lanspeed_bpf_status *status = lanspeed_bpf_get_status();

		json_object_object_add(self_heal, "enabled", json_object_new_boolean(enable_bpf));
		json_object_object_add(self_heal, "early_passthrough",
				       json_object_new_boolean(bpf_runtime_early_passthrough));
		json_object_object_add(self_heal, "recoveries",
				       json_object_new_int64(status ? (int64_t)status->self_heal_count : 0));
		json_object_object_add(self_heal, "failures",
				       json_object_new_int64((int64_t)bpf_runtime_self_heal_failures));
		if (status && status->last_self_heal_reason[0])
			json_object_object_add(self_heal, "last_reason",
					       json_object_new_string(status->last_self_heal_reason));
		if (bpf_runtime_last_self_heal_failure[0])
			json_object_object_add(self_heal, "last_failure",
					       json_object_new_string(bpf_runtime_last_self_heal_failure));
		json_object_object_add(tc_filter, "bpf_tc_self_heal", self_heal);
	}

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
	json_object_object_add(rate_model, "default_active_client_window_ms",
			       json_object_new_int64((int64_t)DEFAULT_ACTIVE_CLIENT_WINDOW_MS));
	json_object_object_add(rate_model, "minimum_active_client_window_ms",
			       json_object_new_int64((int64_t)MIN_ACTIVE_CLIENT_WINDOW_MS));
	json_object_object_add(rate_model, "configured_active_client_window_ms",
			       json_object_new_int64((int64_t)active_client_window_ms));
	json_object_object_add(rate_model, "default_active_client_min_bps",
			       json_object_new_int64((int64_t)DEFAULT_ACTIVE_CLIENT_MIN_BPS));
	json_object_object_add(rate_model, "configured_active_client_min_bps",
			       json_object_new_int64((int64_t)active_client_min_bps));
	json_object_object_add(rate_model, "default_overview_window_samples",
			       json_object_new_int(DEFAULT_OVERVIEW_WINDOW_SAMPLES));
	json_object_object_add(rate_model, "configured_overview_window_samples",
			       json_object_new_int(overview_window_samples));
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
	if (!rate_collector_mode_allows_bpf())
		json_object_array_add(warnings, json_object_new_string("bpf_disabled_by_collector_mode"));
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
	if (active_client_window_clamped)
		json_object_array_add(warnings, json_object_new_string("active_client_window_below_minimum"));
	if (active_client_min_bps_clamped)
		json_object_array_add(warnings, json_object_new_string("active_client_min_bps_below_minimum"));
	if (overview_window_samples_clamped)
		json_object_array_add(warnings, json_object_new_string("overview_window_samples_out_of_range"));
	if (probe->tc_filter_conflict)
		json_object_array_add(warnings, json_object_new_string("tc_filter_conflict"));
	if (dae_tc_preempts_bpf_ingress(probe))
		json_object_array_add(warnings, json_object_new_string("dae_tc_preempts_bpf_ingress"));
	if (enable_bpf && !probe->safe_attach)
		json_object_array_add(warnings, json_object_new_string("unsafe_attach"));
	if (enable_bpf && probe->safe_attach && !probe->bpf_runtime_metrics) {
		json_object_array_add(warnings, json_object_new_string("bpf_runtime_loader_unavailable"));
		json_object_array_add(warnings, json_object_new_string("live_metrics_unavailable"));
	}
	if (nss_daed_should_prefer_bpf(probe))
		json_object_array_add(warnings, json_object_new_string("nss_daed_prefers_bpf"));
	if (nss_daed_nss_fallback_active(probe))
		json_object_array_add(warnings, json_object_new_string("nss_daed_nss_fallback_may_be_inaccurate"));
	if (nss_conntrack_sync_stable_active(probe) && bpf_full_available(probe))
		json_object_array_add(warnings, json_object_new_string("nss_prefers_conntrack_sync"));

	{
		struct json_object *nss_direct = json_object_new_object();
		struct json_object *direct_sources = json_object_new_array();
		struct json_object *direct_forbidden = json_object_new_array();
		json_object_array_add(direct_sources, json_object_new_string(NSS_ECM_STATE_DEV_PATH));
		json_object_array_add(direct_sources, json_object_new_string(NSS_ECM_STATE_DEV_MAJOR_PATH));
		json_object_array_add(direct_sources, json_object_new_string("procfs:/proc/net/arp"));
		json_object_array_add(direct_sources, json_object_new_string(NEIGHBOR_NETLINK_SOURCE));
		json_object_array_add(direct_forbidden, json_object_new_string("defunct_all"));
		json_object_array_add(direct_forbidden, json_object_new_string("flush"));
		json_object_array_add(direct_forbidden, json_object_new_string("decelerate"));
		json_object_object_add(nss_direct, "source", json_object_new_string("lanspeedd_nss_ecm_direct_state"));
		json_object_object_add(nss_direct, "collector_mode", json_object_new_string(NSS_ECM_DIRECT_SOURCE));
		json_object_object_add(nss_direct, "primary_source", json_object_new_string(NSS_ECM_DIRECT_SOURCE));
		json_object_object_add(nss_direct, "supported", json_object_new_boolean(nss_ecm_direct_supported(probe)));
		json_object_object_add(nss_direct, "active", json_object_new_boolean(nss_ecm_direct_overlay_enabled(probe)));
		json_object_object_add(nss_direct, "state_present", json_object_new_boolean(probe->nss_ecm_direct_state));
		json_object_object_add(nss_direct, "state_errno", json_object_new_int(probe->nss_ecm_direct_state_errno));
		json_object_object_add(nss_direct, "state_major", json_object_new_int((int)probe->nss_ecm_direct_state_major));
		json_object_object_add(nss_direct, "source_path", json_object_new_string(probe->nss_ecm_direct_state_source));
		json_object_object_add(nss_direct, "read_only", json_object_new_boolean(true));
		json_object_object_add(nss_direct, "mode", json_object_new_string("Full"));
		json_object_object_add(nss_direct, "confidence", json_object_new_string(nss_ecm_direct_overlay_enabled(probe) ? "high" : "unsupported"));
		json_object_object_add(nss_direct, "coverage", json_object_new_string(NSS_ECM_DIRECT_SOURCE));
		json_object_object_add(nss_direct, "fallback_to", json_object_new_string("conntrack_ecm_sync"));
		json_object_object_add(nss_direct, "fallback_reason", json_object_new_string(nss_ecm_direct_overlay_enabled(probe) ? "" : "state_unavailable_or_unreadable"));
		json_object_object_add(nss_direct, "counter_source", json_object_new_string("ecm_state_adv_stats_from_to_data_total"));
		json_object_object_add(nss_direct, "sources", direct_sources);
		json_object_object_add(nss_direct, "forbidden_writes", direct_forbidden);
		json_object_object_add(nss_direct, "identity_model", json_object_new_string("state sip_address/dip_address + snode_address/dnode_address -> ARP/neighbor -> mac+zone"));
		json_object_object_add(collector, "nss_direct_model", nss_direct);
	}

	json_object_array_add(conntrack_active_when, json_object_new_string("nss_ecm_sync_preferred"));
	json_object_array_add(conntrack_active_when, json_object_new_string("nss_ecm_or_ppe_sync_preferred"));
	json_object_array_add(conntrack_active_when, json_object_new_string("enable_conntrack_fallback=1"));
	json_object_array_add(conntrack_active_when, json_object_new_string("nf_conntrack_acct=1"));
	json_object_array_add(conntrack_inactive_when, json_object_new_string("non_nss_device"));
	json_object_array_add(conntrack_inactive_when, json_object_new_string("bpf_full_unavailable_without_nss_ecm_sync"));
	json_object_array_add(conntrack_inactive_when, json_object_new_string("bpf_full_available_without_nss_ecm_sync"));
	json_object_array_add(conntrack_inactive_when, json_object_new_string("rate_collector_mode=bpf"));
	json_object_array_add(conntrack_inactive_when, json_object_new_string("enable_conntrack_fallback=0"));
	json_object_array_add(conntrack_inactive_when, json_object_new_string("conntrack_acct_disabled"));
	json_object_array_add(conntrack_sources, json_object_new_string("ctnetlink_conntrack_acct_orig_reply_bytes"));
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
	if (nss_conntrack_sync_stable_active(probe))
		json_object_array_add(conntrack_warnings, json_object_new_string("nss_ecm_sync_cadence"));
	if (probe->hardware_flow_offload || probe->software_flow_offload)
		json_object_array_add(conntrack_warnings, json_object_new_string("flow_offload_confidence_low"));

	json_object_object_add(conntrack_directions, "tx_bps", json_object_new_string("NSS ECM/PPE sync only: bytes sent by the LAN endpoint from the client point of view"));
	json_object_object_add(conntrack_directions, "rx_bps", json_object_new_string("NSS ECM/PPE sync only: bytes received by the LAN endpoint from the client point of view"));
	json_object_object_add(conntrack_identity, "primary_key", json_object_new_string("mac+zone"));
	json_object_object_add(conntrack_identity, "ip_role", json_object_new_string("LAN client IP maps to an existing MAC/zone identity and is never the primary identity"));
	json_object_object_add(conntrack_identity, "router_self_policy", json_object_new_string("router-originated proxy traffic is bucketed as router_self and is never attributed to a LAN client"));
	json_object_object_add(conntrack_identity, "excluded_interfaces", json_object_new_string("dae0,dae0peer,tun*,ppp*,wg* are never LAN client MAC/IP sources"));

	json_object_object_add(conntrack, "source", json_object_new_string("lanspeedd_procfs_conntrack_acct"));
	json_object_object_add(conntrack, "configured_mode", json_object_new_string(conn_collector_mode_config_name()));
	json_object_object_add(conntrack, "configured_rate_mode", json_object_new_string(rate_collector_mode_config_name()));
	json_object_object_add(conntrack, "configured_conn_mode", json_object_new_string(conn_collector_mode_config_name()));
	json_object_object_add(conntrack, "enabled", json_object_new_boolean((enable_conntrack_fallback || conn_collector_mode_is_forced()) && rate_collector_mode_allows_conntrack_sync()));
	json_object_object_add(conntrack, "active", json_object_new_boolean(conntrack_fallback_active(probe)));
	json_object_object_add(conntrack, "non_nss_live_rate_policy", json_object_new_string("bpf_only"));
	json_object_object_add(conntrack, "non_nss_conntrack_policy", json_object_new_string("connection_counts_and_diagnostics_only"));
	json_object_object_add(conntrack, "collector_mode", json_object_new_string("conntrack"));
	json_object_object_add(conntrack, "primary_source", json_object_new_string(collector_primary_source(probe)));
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

	apply_runtime_probe_common_warnings(probe);
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
	if (!probe)
		return;

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
	probe->warnings = NULL;
	probe->conflicts = NULL;
	probe->evidence = NULL;
	probe->tc_filters = NULL;
	probe->commands = NULL;
	probe->files = NULL;
	probe->uci = NULL;
	probe->ubus_evidence = NULL;
	probe->source_commands = NULL;
	probe->source_files = NULL;
	probe->source_uci = NULL;
	probe->source_ubus = NULL;
}

static struct json_object *runtime_probe_take_json(struct json_object **slot)
{
	struct json_object *obj;

	if (!slot)
		return NULL;
	obj = *slot;
	*slot = NULL;
	return obj;
}

static const char *probe_mode(const struct runtime_probe *probe)
{
	if (nss_ecm_direct_overlay_enabled(probe))
		return "Full";
	if (!probe->tc && !conntrack_fallback_active(probe))
		return "Unsupported";
	if (conntrack_primary_preferred(probe))
		return "Degraded";
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
		json_object_object_add(nss, "direct_supported", json_object_new_boolean(nss_ecm_direct_supported(probe)));
		json_object_object_add(nss, "direct_enabled", json_object_new_boolean(nss_ecm_direct_overlay_enabled(probe)));
		json_object_object_add(nss, "direct_source", json_object_new_string(NSS_ECM_DIRECT_SOURCE));
		json_object_object_add(nss, "fallback_reason", json_object_new_string(nss_ecm_direct_overlay_enabled(probe) ? "" : "state_unavailable_or_unreadable"));
		json_object_object_add(nss, "direct_state_present", json_object_new_boolean(probe->nss_ecm_direct_state));
		json_object_object_add(nss, "direct_state_errno", json_object_new_int(probe->nss_ecm_direct_state_errno));
		json_object_object_add(nss, "direct_state_major", json_object_new_int((int)probe->nss_ecm_direct_state_major));
		json_object_object_add(nss, "direct_source_path", json_object_new_string(probe->nss_ecm_direct_state_source));
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
			nss_conntrack_sync_stable_active(probe) ? "ecm_conntrack_sync"
			: nss_ecm_direct_overlay_enabled(probe) ? "ecm_state_direct"
			: probe->nss_ppe_active ? "ppe_conntrack_sync"
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
	json_object_object_add(dae, "dae_running", json_object_new_boolean(probe->dae_running));
	json_object_object_add(dae, "daed_running", json_object_new_boolean(probe->daed_running));
	json_object_object_add(dae, "dae_process", json_object_new_boolean(probe->dae_process));
	json_object_object_add(dae, "daed_process", json_object_new_boolean(probe->daed_process));
	json_object_object_add(dae, "runtime_active", json_object_new_boolean(daed_runtime_active(probe)));
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

	json_object_object_add(sources, "command", runtime_probe_take_json(&probe->source_commands));
	json_object_object_add(sources, "file", runtime_probe_take_json(&probe->source_files));
	json_object_object_add(sources, "uci", runtime_probe_take_json(&probe->source_uci));
	json_object_object_add(sources, "ubus", runtime_probe_take_json(&probe->source_ubus));

	json_object_object_add(probe->evidence, "source", json_object_new_string("lanspeedd_runtime_probe"));
	json_object_object_add(probe->evidence, "method", json_object_new_string(method));
	json_object_object_add(probe->evidence, "read_only", json_object_new_boolean(true));
	json_object_object_add(probe->evidence, "probe_sources", sources);
	json_object_object_add(probe->evidence, "commands", runtime_probe_take_json(&probe->commands));
	json_object_object_add(probe->evidence, "files", runtime_probe_take_json(&probe->files));
	json_object_object_add(probe->evidence, "uci", runtime_probe_take_json(&probe->uci));
	json_object_object_add(probe->evidence, "ubus", runtime_probe_take_json(&probe->ubus_evidence));
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
	json_object_object_add(capabilities, "nss_ecm_direct", json_object_new_boolean(probe ? nss_ecm_direct_overlay_enabled(probe) : false));
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

static uint64_t monotonic_time_ms(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
		return 0;

	return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
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

static const struct conntrack_client_sample *find_previous_nss_ecm_direct_sample(
	const char *identity_key)
{
	size_t i;

	for (i = 0; i < previous_nss_ecm_direct_sample_count; i++) {
		if (!strcmp(previous_nss_ecm_direct_samples[i].identity_key, identity_key))
			return &previous_nss_ecm_direct_samples[i];
	}

	return NULL;
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

static uint64_t conntrack_refresh_last_seen(
	const struct conntrack_client_sample *current,
	const struct conntrack_client_sample *previous)
{
	if (!current)
		return 0;
	if (!previous)
		return current->last_seen_ms;
	if (current->tx_bytes != previous->tx_bytes ||
	    current->rx_bytes != previous->rx_bytes)
		return current->last_seen_ms;
	return previous->last_seen_ms;
}

static void add_conntrack_common_warnings(const struct runtime_probe *probe,
					  struct json_object *warnings)
{
	if (nss_conntrack_sync_stable_active(probe)) {
		add_string_unique(warnings, "nss_ecm_sync_cadence");
		if (bpf_full_available(probe))
			add_string_unique(warnings, "nss_prefers_conntrack_sync");
		if (nss_daed_nss_fallback_active(probe))
			add_string_unique(warnings, "nss_daed_nss_fallback_may_be_inaccurate");
	} else {
		add_string_unique(warnings, "conntrack_routed_nat_only");
	}
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
		/* NSS syncs counters back to conntrack; downgrade
		 * the blanket "flow_offload_confidence_low" to a softer
		 * warning that reflects the actual sync cadence. */
		if (nss_conntrack_sync_stable_active(probe))
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
	json_object_object_add(identity, "ip_identity", json_object_new_string("LAN IPs are attributes mapped through ARP/neighbor, never primary identity keys"));
	json_object_object_add(identity, "mac_source", json_object_new_string(ARP_PROCFS_PATH));
	json_object_object_add(identity, "neighbor_source", json_object_new_string(NEIGHBOR_NETLINK_SOURCE));
	json_object_object_add(identity, "excluded_interfaces", json_object_new_string("dae0,dae0peer,tun*,ppp*,wg*"));
	json_object_object_add(identity, "missing_mac_policy", json_object_new_string("skip_conntrack_entry_without_fabricating_client"));
	json_object_object_add(evidence, "identity_model", identity);
}

static void add_clients_identity_evidence(struct json_object *parent)
{
	struct json_object *evidence = NULL;
	struct json_object *identity_model = NULL;
	struct json_object *existing_identity = NULL;
	struct json_object *primary_key = json_object_new_array();
	struct json_object *sources = json_object_new_array();
	struct json_object *direction = json_object_new_object();
	struct json_object *excluded = json_object_new_array();

	if (!parent)
		goto out;

	if (!json_object_object_get_ex(parent, "evidence", &evidence) ||
	    !json_object_is_type(evidence, json_type_object)) {
		evidence = json_object_new_object();
		json_object_object_add(parent, "evidence", evidence);
		json_object_object_add(evidence, "source",
				       json_object_new_string("lanspeedd_identity_model"));
		json_object_object_add(evidence, "method",
				       json_object_new_string("clients"));
		json_object_object_add(evidence, "read_only",
				       json_object_new_boolean(true));
		json_object_object_add(evidence, "live_metrics",
				       json_object_new_boolean(false));
	}

	if (json_object_object_get_ex(evidence, "identity_model", &existing_identity) &&
	    json_object_is_type(existing_identity, json_type_object)) {
		identity_model = existing_identity;
	} else {
		identity_model = json_object_new_object();
		json_object_object_add(evidence, "identity_model", identity_model);
	}

	json_object_array_add(primary_key, json_object_new_string("mac"));
	json_object_array_add(primary_key, json_object_new_string("zone"));
	json_object_object_add(identity_model, "primary_key", primary_key);
	primary_key = NULL;
	json_object_object_add(identity_model, "attached_fields",
			       json_object_new_string("ips,hostname,interface,last_seen"));
	json_object_object_add(identity_model, "ip_identity",
			       json_object_new_string("addresses are attributes only, not unique identity keys"));

	json_object_array_add(sources, json_object_new_string("dhcp_lease"));
	json_object_array_add(sources, json_object_new_string("arp_nd_neighbor"));
	json_object_array_add(sources, json_object_new_string("hostapd_nl80211"));
	json_object_array_add(sources, json_object_new_string("netifd_ubus"));
	json_object_object_add(identity_model, "merge_sources", sources);
	sources = NULL;

	json_object_object_add(direction, "tx_bps",
			       json_object_new_string("client-originated traffic from the client point of view"));
	json_object_object_add(direction, "rx_bps",
			       json_object_new_string("traffic to client from the client point of view"));
	json_object_object_add(identity_model, "direction", direction);
	direction = NULL;

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
	excluded = NULL;

out:
	json_object_put(primary_key);
	json_object_put(sources);
	json_object_put(direction);
	json_object_put(excluded);
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
	json_object_array_add(sources, json_object_new_string(NEIGHBOR_NETLINK_SOURCE));
	json_object_array_add(sources, json_object_new_string("netlink:ctnetlink"));
	json_object_array_add(forbidden, json_object_new_string("firewall_forward_chain_counters"));
	json_object_array_add(forbidden, json_object_new_string("iptables_forward_chain_counters"));
	json_object_array_add(forbidden, json_object_new_string("nft_forward_chain_counters"));
	json_object_array_add(forbidden, json_object_new_string("nlbwmon_counters"));

	json_object_object_add(evidence, "source", json_object_new_string(conntrack_stats_runtime_source(stats)));
	json_object_object_add(evidence, "method", json_object_new_string("clients"));
	json_object_object_add(evidence, "read_only", json_object_new_boolean(true));
	if (nss_conntrack_sync_reader_available(probe)) {
		json_object_object_add(evidence, "collector_mode", json_object_new_string("conntrack_ecm_sync"));
		json_object_object_add(evidence, "primary_source", json_object_new_string("nss_conntrack_sync"));
		json_object_object_add(evidence, "coverage", json_object_new_string("nss_ecm_sync"));
		json_object_object_add(evidence, "coverage_warning", json_object_new_string("nss_ecm_sync_cadence"));
	} else {
		json_object_object_add(evidence, "collector_mode", json_object_new_string("conntrack"));
		json_object_object_add(evidence, "primary_source", json_object_new_string("conntrack"));
		json_object_object_add(evidence, "coverage", json_object_new_string("routed_nat_only"));
		json_object_object_add(evidence, "coverage_warning", json_object_new_string("conntrack_routed_nat_only"));
	}
	json_object_object_add(evidence, "mode", json_object_new_string("Degraded"));
	json_object_object_add(evidence, "active", json_object_new_boolean(active));
	json_object_object_add(evidence, "live_metrics", json_object_new_boolean(false));
	json_object_object_add(evidence, "bpf_runtime_metrics", json_object_new_boolean(probe->bpf_runtime_metrics));
	json_object_object_add(evidence, "confidence", json_object_new_string(conntrack_clients_read_confidence(probe)));
	json_object_object_add(evidence, "counter_source", json_object_new_string(conntrack_stats_counter_source(stats)));
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
		json_object_object_add(evidence, "netlink_attempted", json_object_new_boolean(stats->netlink_attempted));
		json_object_object_add(evidence, "netlink_read", json_object_new_boolean(stats->netlink_read));
		json_object_object_add(evidence, "netlink_errno", json_object_new_int(stats->netlink_errno));
		json_object_object_add(evidence, "procfs_read", json_object_new_boolean(stats->procfs_read));
		json_object_object_add(evidence, "source_path", json_object_new_string(stats->source_path[0] ? stats->source_path : ""));
		json_object_object_add(evidence, "snapshot_pending", json_object_new_boolean(stats->snapshot_pending));
		json_object_object_add(evidence, "current_clients", json_object_new_int64((int64_t)stats->current_clients));
		json_object_object_add(evidence, "emitted_clients", json_object_new_int64((int64_t)stats->emitted_clients));
		json_object_object_add(evidence, "skipped_no_arp", json_object_new_int64((int64_t)stats->skipped_no_arp));
		json_object_object_add(evidence, "no_lan_flows", json_object_new_int64((int64_t)stats->no_lan_flows));
		json_object_object_add(evidence, "both_lan_flows", json_object_new_int64((int64_t)stats->both_lan_flows));
		json_object_object_add(evidence, "src_lan_flows", json_object_new_int64((int64_t)stats->src_lan_flows));
		json_object_object_add(evidence, "dst_lan_flows", json_object_new_int64((int64_t)stats->dst_lan_flows));
		json_object_object_add(evidence, "ipv4_lan_flows", json_object_new_int64((int64_t)stats->ipv4_lan_flows));
		json_object_object_add(evidence, "ipv6_lan_flows", json_object_new_int64((int64_t)stats->ipv6_lan_flows));
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
	uint64_t udp_dns_conns_total = 0;
	uint64_t udp_other_conns_total = 0;
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
		uint64_t last_seen_ms;
		size_t ip_index;

		previous = find_previous_conntrack_sample(current[i].identity_key);
		if (previous_conntrack_snapshot_valid && previous) {
			tx_bps = delta_bps(current[i].tx_bytes, previous->tx_bytes, delta_ms, &counter_anomaly);
			rx_bps = delta_bps(current[i].rx_bytes, previous->rx_bytes, delta_ms, &counter_anomaly);
		}
		if (counter_anomaly)
			add_string_unique(base_warnings, "counter_anomaly");
		last_seen_ms = conntrack_refresh_last_seen(&current[i], previous);
		current[i].last_seen_ms = last_seen_ms;

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
		json_object_object_add(client, "udp_dns_conns", json_object_new_int64((int64_t)current[i].udp_dns_conns));
		json_object_object_add(client, "udp_other_conns", json_object_new_int64((int64_t)current[i].udp_other_conns));
		json_object_object_add(client, "sample_ms", json_object_new_int64((int64_t)now_ms));
		json_object_object_add(client, "last_seen", json_object_new_int64((int64_t)last_seen_ms));
		json_object_object_add(client, "collector_mode",
			json_object_new_string(conntrack_stats_collector_mode(probe, stats)));
		json_object_object_add(client, "confidence", json_object_new_string(conntrack_clients_read_confidence(probe)));
		json_object_object_add(client, "warnings", warnings);
		json_object_array_add(clients, client);
		stats->emitted_clients++;
		tcp_conns_total += current[i].tcp_conns;
		udp_conns_total += current[i].udp_conns;
		udp_dns_conns_total += current[i].udp_dns_conns;
		udp_other_conns_total += current[i].udp_other_conns;
	}

	json_object_object_add(root, "tcp_conns_total", json_object_new_int64((int64_t)tcp_conns_total));
	json_object_object_add(root, "udp_conns_total", json_object_new_int64((int64_t)udp_conns_total));
	json_object_object_add(root, "udp_dns_conns_total", json_object_new_int64((int64_t)udp_dns_conns_total));
	json_object_object_add(root, "udp_other_conns_total", json_object_new_int64((int64_t)udp_other_conns_total));
	json_object_object_add(root, "conntrack_entries_seen", json_object_new_int64((int64_t)stats->entries_seen));
	json_object_object_add(root, "conntrack_entries_matched", json_object_new_int64((int64_t)stats->entries_matched));
	json_object_object_add(root, "conntrack_parse_errors", json_object_new_int64((int64_t)stats->malformed_lines));
	json_object_object_add(root, "conn_source", json_object_new_string(conntrack_stats_source(stats)));
	json_object_object_add(root, "conn_semantics", json_object_new_string("conntrack_current_tcp_established_assured_udp_tracked_dns_split"));

	memcpy(previous_conntrack_samples, current,
	       current_count * sizeof(struct conntrack_client_sample));
	previous_conntrack_sample_count = current_count;
	previous_conntrack_snapshot_ms = now_ms;
	previous_conntrack_snapshot_valid = true;
}

static void bpf_collect_samples(void)
{
	struct json_object *discard_warnings = json_object_new_array();
	uint64_t now_ms = monotonic_time_ms();
	size_t max_folded = max_clients > 0 && max_clients < DEFAULT_MAX_CLIENTS ?
			    (size_t)max_clients : DEFAULT_MAX_CLIENTS;

	bpf_collect_snapshot(&bpf_cache, max_folded, now_ms, discard_warnings);
	json_object_put(discard_warnings);
}

static void bpf_collect_tick(struct uloop_timeout *t)
{
	if (bpf_runtime_enabled) {
		struct runtime_probe probe;

		init_runtime_probe(&probe);
		load_cached_runtime_probe(&probe);
		(void)bpf_runtime_refresh_attach_policy(&probe);
		free_runtime_probe(&probe);

		bpf_runtime_recover_if_needed("periodic_tc_filter_check");
		bpf_collect_samples();
	}
	uloop_timeout_set(t, refresh_interval_ms > 0 ? refresh_interval_ms :
						       DEFAULT_REFRESH_INTERVAL_MS);
}

static void add_bpf_clients_evidence(struct json_object *root,
				     const struct runtime_probe *probe,
				     uint64_t delta_ms, size_t emitted_clients,
				     uint64_t approx_tcp_tuples,
				     uint64_t approx_udp_tuples)
{
	struct json_object *evidence = json_object_new_object();
	struct json_object *sources = json_object_new_array();
	const struct lanspeed_bpf_status *status = lanspeed_bpf_get_status();

	(void)probe;

	json_object_array_add(sources, json_object_new_string("bpf:lanspeed_clients"));
	json_object_array_add(sources, json_object_new_string("procfs:/proc/net/arp"));
	json_object_array_add(sources, json_object_new_string(NEIGHBOR_NETLINK_SOURCE));

	json_object_object_add(evidence, "collector_mode", json_object_new_string("bpf"));
	json_object_object_add(evidence, "primary_source", json_object_new_string("bpf"));
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
	json_object_object_add(evidence, "bpf_approx_tcp_tuples",
			       json_object_new_int64((int64_t)approx_tcp_tuples));
	json_object_object_add(evidence, "bpf_approx_udp_tuples",
			       json_object_new_int64((int64_t)approx_udp_tuples));
	json_object_object_add(evidence, "bpf_approx_tuple_semantics",
			       json_object_new_string("diagnostic_only_not_conntrack_current_table"));
	if (nss_daed_should_prefer_bpf(probe)) {
		struct json_object *warnings = json_object_new_array();
		json_object_array_add(warnings, json_object_new_string("nss_daed_prefers_bpf"));
		json_object_object_add(evidence, "warnings", warnings);
	}
	if (status) {
		json_object_object_add(evidence, "bpf_object_path",
				       json_object_new_string(status->object_path));
		json_object_object_add(evidence, "attached_hooks",
				       json_object_new_int((int)status->attached_hook_count));
		json_object_object_add(evidence, "last_sample_count",
				       json_object_new_int((int)status->last_sample_count));
		json_object_object_add(evidence, "bpf_tc_self_heal_count",
				       json_object_new_int64((int64_t)status->self_heal_count));
		if (status->last_self_heal_reason[0])
			json_object_object_add(evidence, "bpf_tc_self_heal_reason",
					       json_object_new_string(status->last_self_heal_reason));
	}
	json_object_object_add(root, "evidence", evidence);
}

static bool collect_bpf_clients(struct json_object *root,
				struct json_object *clients,
				const struct runtime_probe *probe)
{
	struct bpf_rate_sample rates[DEFAULT_MAX_CLIENTS];
	uint64_t delta_ms;
	size_t emitted = 0;
	uint64_t approx_tcp_tuples = 0;
	uint64_t approx_udp_tuples = 0;
	size_t max_rates = max_clients > 0 && max_clients < DEFAULT_MAX_CLIENTS ?
		(size_t)max_clients : DEFAULT_MAX_CLIENTS;
	size_t i;

	if (!bpf_runtime_metrics_available(probe))
		return false;

	emitted = bpf_build_rate_samples(&bpf_cache, rates, max_rates, &delta_ms);
	if (emitted == 0)
		return false;

	for (i = 0; i < emitted; i++) {
		struct json_object *client = json_object_new_object();
		struct json_object *ips = json_object_new_array();
		struct json_object *warnings = json_object_new_array();
		const struct bpf_rate_sample *rate = &rates[i];
		size_t j;

		if (rate->counter_anomaly)
			add_string_unique(warnings, "counter_anomaly");

		for (j = 0; j < rate->ip_count; j++)
			json_object_array_add(ips, json_object_new_string(rate->ips[j]));

		json_object_object_add(client, "mac", json_object_new_string(rate->mac));
		json_object_object_add(client, "identity_key",
				       json_object_new_string(rate->identity_key));
		json_object_object_add(client, "zone", json_object_new_string(rate->zone));
		json_object_object_add(client, "interface",
				       json_object_new_string(rate->ifname));
		json_object_object_add(client, "ips", ips);
		{
			const char *ip_ptrs[BPF_MAX_CLIENT_IPS];
			const char *name;
			size_t k;
			for (k = 0; k < rate->ip_count; k++)
				ip_ptrs[k] = rate->ips[k];
			name = hostname_lookup(rate->mac, ip_ptrs, rate->ip_count);
			json_object_object_add(client, "hostname",
			                       name ? json_object_new_string(name) : NULL);
		}
		json_object_object_add(client, "rx_bps",
				       json_object_new_int64((int64_t)rate->rx_bps));
		json_object_object_add(client, "tx_bps",
				       json_object_new_int64((int64_t)rate->tx_bps));
		json_object_object_add(client, "rx_bytes",
				       json_object_new_int64((int64_t)rate->rx_bytes));
		json_object_object_add(client, "tx_bytes",
				       json_object_new_int64((int64_t)rate->tx_bytes));
		approx_tcp_tuples += rate->bpf_approx_tcp_tuples;
		approx_udp_tuples += rate->bpf_approx_udp_tuples;
		json_object_object_add(client, "sample_ms",
				       json_object_new_int64((int64_t)rate->sample_ms));
		json_object_object_add(client, "last_seen",
				       json_object_new_int64((int64_t)rate->last_seen_ms));
		json_object_object_add(client, "collector_mode",
				       json_object_new_string("bpf"));
		json_object_object_add(client, "confidence",
				       json_object_new_string("high"));
		json_object_object_add(client, "warnings", warnings);
		json_object_array_add(clients, client);
	}

	add_bpf_clients_evidence(root, probe, delta_ms, emitted,
				 approx_tcp_tuples, approx_udp_tuples);
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

	if (!conntrack_clients_read_active(probe)) {
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
	read_ok = read_conntrack_snapshot_mode(current, &current_count, max_samples,
					       now_ms, warnings, &stats,
					       conn_collector_mode);
	if (!read_ok) {
		add_conntrack_clients_evidence(root, probe, warnings, &stats, true);
		return false;
	}

	emit_conntrack_clients(root, clients, probe, current, current_count, now_ms, warnings, &stats);
	add_conntrack_clients_evidence(root, probe, warnings, &stats, true);
	return true;
}

static bool json_client_identity_key(struct json_object *client,
				     const char **identity_key)
{
	struct json_object *obj = NULL;

	if (!client || !identity_key)
		return false;
	if (!json_object_object_get_ex(client, "identity_key", &obj))
		return false;
	*identity_key = json_object_get_string(obj);
	return *identity_key && (*identity_key)[0];
}

static struct json_object *json_client_find_by_identity(struct json_object *clients,
							const char *identity_key,
							size_t *index_out)
{
	size_t i;
	size_t count;

	if (!clients || !identity_key)
		return NULL;

	count = json_object_array_length(clients);
	for (i = 0; i < count; i++) {
		struct json_object *client = json_object_array_get_idx(clients, i);
		const char *existing_key = NULL;

		if (json_client_identity_key(client, &existing_key) &&
		    !strcmp(existing_key, identity_key)) {
			if (index_out)
				*index_out = i;
			return client;
		}
	}

	return NULL;
}

static bool direct_rate_has_data(uint64_t tx_bps, uint64_t rx_bps)
{
	return tx_bps > 0 || rx_bps > 0;
}

static void add_nss_stable_overlay_evidence(struct json_object *root,
					    struct json_object *warnings,
					    const struct nss_ecm_direct_stats *direct_stats,
					    size_t direct_overlay_clients,
					    size_t sync_fallback_clients,
					    size_t emitted_clients)
{
	struct json_object *evidence = json_object_new_object();
	struct json_object *sources = json_object_new_array();

	json_object_array_add(sources, json_object_new_string("netlink:ctnetlink"));
	json_object_array_add(sources, json_object_new_string("procfs:/proc/net/nf_conntrack"));
	json_object_array_add(sources, json_object_new_string(NSS_ECM_STATE_DEV_PATH));
	json_object_array_add(sources, json_object_new_string(NSS_ECM_STATE_DEV_MAJOR_PATH));
	json_object_array_add(sources, json_object_new_string("procfs:/proc/net/arp"));
	json_object_array_add(sources, json_object_new_string(NEIGHBOR_NETLINK_SOURCE));

	json_object_object_add(evidence, "source", json_object_new_string("lanspeedd_nss_stable_collector"));
	json_object_object_add(evidence, "method", json_object_new_string("clients"));
	json_object_object_add(evidence, "collector_mode", json_object_new_string(
		(direct_overlay_clients > 0 && sync_fallback_clients > 0) ?
			"nss_ecm_direct+conntrack_ecm_sync" :
			(direct_overlay_clients > 0 ? NSS_ECM_DIRECT_SOURCE : "conntrack_ecm_sync")));
	json_object_object_add(evidence, "primary_source", json_object_new_string("nss_conntrack_sync"));
	json_object_object_add(evidence, "coverage", json_object_new_string(
		(direct_overlay_clients > 0 && sync_fallback_clients > 0) ?
			"nss_ecm_direct+conntrack_ecm_sync" :
			(direct_overlay_clients > 0 ? NSS_ECM_DIRECT_SOURCE : "nss_ecm_sync")));
	json_object_object_add(evidence, "coverage_warning", json_object_new_string("nss_ecm_sync_cadence"));
	json_object_object_add(evidence, "mode", json_object_new_string("Degraded"));
	json_object_object_add(evidence, "active", json_object_new_boolean(true));
	json_object_object_add(evidence, "live_metrics", json_object_new_boolean(false));
	json_object_object_add(evidence, "read_only", json_object_new_boolean(true));
	json_object_object_add(evidence, "confidence", json_object_new_string("medium"));
	json_object_object_add(evidence, "counter_source", json_object_new_string("ctnetlink_conntrack_acct_orig_reply_bytes"));
	json_object_object_add(evidence, "sources", sources);
	json_object_object_add(evidence, "emitted_clients", json_object_new_int64((int64_t)emitted_clients));
	json_object_object_add(evidence, "direct_flows_seen", json_object_new_int64((int64_t)(direct_stats ? direct_stats->entries_seen : 0)));
	json_object_object_add(evidence, "direct_flows_matched", json_object_new_int64((int64_t)(direct_stats ? direct_stats->entries_matched : 0)));
	json_object_object_add(evidence, "direct_overlay_clients", json_object_new_int64((int64_t)direct_overlay_clients));
	json_object_object_add(evidence, "sync_fallback_clients", json_object_new_int64((int64_t)sync_fallback_clients));
	json_object_object_add(evidence, "warnings", warnings);
	add_conntrack_identity_model(evidence);
	json_object_object_add(root, "evidence", evidence);
}

static void add_nss_ecm_direct_clients_evidence(struct json_object *root,
						const struct runtime_probe *probe,
						struct json_object *warnings,
						const struct nss_ecm_direct_stats *stats,
						bool active)
{
	struct json_object *evidence = json_object_new_object();
	struct json_object *sources = json_object_new_array();
	struct json_object *forbidden = json_object_new_array();

	(void)probe;

	json_object_array_add(sources, json_object_new_string(NSS_ECM_STATE_DEV_PATH));
	json_object_array_add(sources, json_object_new_string(NSS_ECM_STATE_DEV_MAJOR_PATH));
	json_object_array_add(sources, json_object_new_string("procfs:/proc/net/arp"));
	json_object_array_add(sources, json_object_new_string(NEIGHBOR_NETLINK_SOURCE));
	json_object_array_add(forbidden, json_object_new_string("defunct_all"));
	json_object_array_add(forbidden, json_object_new_string("flush"));
	json_object_array_add(forbidden, json_object_new_string("decelerate"));

	json_object_object_add(evidence, "source", json_object_new_string("lanspeedd_nss_ecm_direct_state"));
	json_object_object_add(evidence, "method", json_object_new_string("clients"));
	json_object_object_add(evidence, "collector_mode", json_object_new_string("nss_ecm_direct"));
	json_object_object_add(evidence, "primary_source", json_object_new_string(NSS_ECM_DIRECT_SOURCE));
	json_object_object_add(evidence, "mode", json_object_new_string("Full"));
	json_object_object_add(evidence, "active", json_object_new_boolean(active));
	json_object_object_add(evidence, "live_metrics", json_object_new_boolean(active));
	json_object_object_add(evidence, "read_only", json_object_new_boolean(true));
	json_object_object_add(evidence, "confidence", json_object_new_string(active ? "high" : "unsupported"));
	json_object_object_add(evidence, "coverage", json_object_new_string(NSS_ECM_DIRECT_SOURCE));
	json_object_object_add(evidence, "counter_source", json_object_new_string("ecm_state_adv_stats_from_to_data_total"));
	json_object_object_add(evidence, "sources", sources);
	json_object_object_add(evidence, "forbidden_writes", forbidden);
	if (stats) {
		json_object_object_add(evidence, "state_attempted", json_object_new_boolean(stats->state_attempted));
		json_object_object_add(evidence, "state_read", json_object_new_boolean(stats->state_read));
		json_object_object_add(evidence, "state_errno", json_object_new_int(stats->state_errno));
		json_object_object_add(evidence, "state_major", json_object_new_int((int)stats->state_major));
		json_object_object_add(evidence, "source_path", json_object_new_string(stats->source_path[0] ? stats->source_path : ""));
		json_object_object_add(evidence, "snapshot_pending", json_object_new_boolean(stats->snapshot_pending));
		json_object_object_add(evidence, "current_clients", json_object_new_int64((int64_t)stats->current_clients));
		json_object_object_add(evidence, "emitted_clients", json_object_new_int64((int64_t)stats->emitted_clients));
		json_object_object_add(evidence, "flows_seen", json_object_new_int64((int64_t)stats->entries_seen));
		json_object_object_add(evidence, "flows_matched", json_object_new_int64((int64_t)stats->entries_matched));
		json_object_object_add(evidence, "skipped_no_arp", json_object_new_int64((int64_t)stats->skipped_no_arp));
		json_object_object_add(evidence, "no_lan_flows", json_object_new_int64((int64_t)stats->no_lan_flows));
		json_object_object_add(evidence, "both_lan_flows", json_object_new_int64((int64_t)stats->both_lan_flows));
		json_object_object_add(evidence, "src_lan_flows", json_object_new_int64((int64_t)stats->src_lan_flows));
		json_object_object_add(evidence, "dst_lan_flows", json_object_new_int64((int64_t)stats->dst_lan_flows));
		json_object_object_add(evidence, "ipv4_lan_flows", json_object_new_int64((int64_t)stats->ipv4_lan_flows));
		json_object_object_add(evidence, "ipv6_lan_flows", json_object_new_int64((int64_t)stats->ipv6_lan_flows));
		json_object_object_add(evidence, "malformed_lines", json_object_new_int64((int64_t)stats->malformed_lines));
	}
	json_object_object_add(evidence, "warnings", warnings);
	add_conntrack_identity_model(evidence);
	json_object_object_add(root, "evidence", evidence);
}

static bool collect_nss_ecm_direct_clients(struct json_object *root,
					   struct json_object *clients,
					   const struct runtime_probe *probe)
{
	struct conntrack_client_sample current[DEFAULT_MAX_CLIENTS];
	struct nss_ecm_direct_stats stats;
	struct json_object *warnings = json_object_new_array();
	uint64_t now_ms = monotonic_time_ms();
	uint64_t delta_ms = previous_nss_ecm_direct_snapshot_valid ?
		(now_ms - previous_nss_ecm_direct_snapshot_ms) : 0;
	size_t current_count = 0;
	size_t max_samples = max_clients > 0 && max_clients < DEFAULT_MAX_CLIENTS ?
		(size_t)max_clients : DEFAULT_MAX_CLIENTS;
	uint64_t tcp_conns_total = 0;
	uint64_t udp_conns_total = 0;
	size_t i;
	bool read_ok;

	if (!nss_ecm_direct_preferred(probe)) {
		add_string_unique(warnings, "nss_ecm_direct_unavailable");
		add_nss_ecm_direct_clients_evidence(root, probe, warnings, NULL, false);
		return false;
	}

	add_string_unique(warnings, "nss_ecm_direct_active");
	if (bpf_full_available(probe) && !nss_conntrack_sync_stable_active(probe))
		add_string_unique(warnings, "nss_prefers_direct");

	read_ok = read_nss_ecm_direct_snapshot(current, &current_count, max_samples,
					       now_ms, warnings, &stats);
	if (!read_ok) {
		add_nss_ecm_direct_clients_evidence(root, probe, warnings, &stats, false);
		return false;
	}

	if (!previous_nss_ecm_direct_snapshot_valid) {
		stats.snapshot_pending = true;
		add_string_unique(warnings, "nss_ecm_direct_snapshot_pending");
	} else if (now_ms < previous_nss_ecm_direct_snapshot_ms) {
		stats.snapshot_pending = true;
		add_string_unique(warnings, "time_rollback");
		delta_ms = 0;
	}

	for (i = 0; i < current_count; i++) {
		const struct conntrack_client_sample *previous;
		struct json_object *client;
		struct json_object *ips;
		struct json_object *client_warnings;
		bool counter_anomaly = false;
		uint64_t tx_bps = 0;
		uint64_t rx_bps = 0;
		size_t ip_index;

		previous = find_previous_nss_ecm_direct_sample(current[i].identity_key);
		if (previous_nss_ecm_direct_snapshot_valid && previous) {
			tx_bps = delta_bps(current[i].tx_bytes, previous->tx_bytes,
					   delta_ms, &counter_anomaly);
			rx_bps = delta_bps(current[i].rx_bytes, previous->rx_bytes,
					   delta_ms, &counter_anomaly);
		}
		if (counter_anomaly)
			add_string_unique(warnings, "counter_anomaly");

		client = json_object_new_object();
		ips = json_object_new_array();
		client_warnings = json_object_get(warnings);
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
		json_object_object_add(client, "udp_dns_conns", json_object_new_int(0));
		json_object_object_add(client, "udp_other_conns", json_object_new_int64((int64_t)current[i].udp_conns));
		json_object_object_add(client, "sample_ms", json_object_new_int64((int64_t)now_ms));
		json_object_object_add(client, "last_seen", json_object_new_int64((int64_t)current[i].last_seen_ms));
		json_object_object_add(client, "collector_mode", json_object_new_string(NSS_ECM_DIRECT_SOURCE));
		json_object_object_add(client, "confidence", json_object_new_string("high"));
		json_object_object_add(client, "warnings", client_warnings);
		json_object_array_add(clients, client);
		stats.emitted_clients++;
		tcp_conns_total += current[i].tcp_conns;
		udp_conns_total += current[i].udp_conns;
	}

	json_object_object_add(root, "tcp_conns_total", json_object_new_int64((int64_t)tcp_conns_total));
	json_object_object_add(root, "udp_conns_total", json_object_new_int64((int64_t)udp_conns_total));
	json_object_object_add(root, "udp_dns_conns_total", json_object_new_int(0));
	json_object_object_add(root, "udp_other_conns_total", json_object_new_int64((int64_t)udp_conns_total));
	json_object_object_add(root, "nss_ecm_direct_flows_seen", json_object_new_int64((int64_t)stats.entries_seen));
	json_object_object_add(root, "nss_ecm_direct_flows_matched", json_object_new_int64((int64_t)stats.entries_matched));
	json_object_object_add(root, "nss_ecm_direct_parse_errors", json_object_new_int64((int64_t)stats.malformed_lines));
	json_object_object_add(root, "conn_source", json_object_new_string(NSS_ECM_DIRECT_SOURCE));
	json_object_object_add(root, "conn_semantics", json_object_new_string("nss_ecm_direct_state_current_tcp_udp_protocol_counts"));

	memcpy(previous_nss_ecm_direct_samples, current,
	       current_count * sizeof(struct conntrack_client_sample));
	previous_nss_ecm_direct_sample_count = current_count;
	previous_nss_ecm_direct_snapshot_ms = now_ms;
	previous_nss_ecm_direct_snapshot_valid = true;

	add_nss_ecm_direct_clients_evidence(root, probe, warnings, &stats, true);
	return true;
}

static bool collect_nss_stable_clients(struct json_object *root,
				       struct json_object *clients,
				       const struct runtime_probe *probe)
{
	struct json_object *sync_root = json_object_new_object();
	struct json_object *sync_clients = json_object_new_array();
	struct json_object *warnings = json_object_new_array();
	struct json_object *value = NULL;
	struct nss_ecm_direct_stats direct_stats;
	size_t direct_overlay_clients = 0;
	size_t sync_fallback_clients = 0;
	size_t i;
	bool sync_ok;
	bool direct_ok = false;
	bool direct_attempted = false;

	memset(&direct_stats, 0, sizeof(direct_stats));
	json_object_object_add(sync_root, "clients", sync_clients);

	sync_ok = collect_conntrack_procfs_clients(sync_root, sync_clients, probe);
	if (!sync_ok) {
		json_object_put(sync_root);
		json_object_put(warnings);
		return collect_nss_ecm_direct_clients(root, clients, probe);
	}

	if (nss_ecm_direct_overlay_enabled(probe)) {
		struct conntrack_client_sample direct_current[DEFAULT_MAX_CLIENTS];
		struct json_object *direct_warnings = json_object_new_array();
		uint64_t now_ms = monotonic_time_ms();
		uint64_t delta_ms = previous_nss_ecm_direct_snapshot_valid ?
			(now_ms - previous_nss_ecm_direct_snapshot_ms) : 0;
		size_t direct_count = 0;
		size_t max_samples = max_clients > 0 && max_clients < DEFAULT_MAX_CLIENTS ?
			(size_t)max_clients : DEFAULT_MAX_CLIENTS;

		direct_attempted = true;
		direct_ok = read_nss_ecm_direct_snapshot(direct_current, &direct_count,
							 max_samples, now_ms,
							 direct_warnings,
							 &direct_stats);
		for (i = 0; i < json_object_array_length(direct_warnings); i++) {
			struct json_object *entry = json_object_array_get_idx(direct_warnings, i);
			if (entry)
				add_string_unique(warnings, json_object_get_string(entry));
		}
		json_object_put(direct_warnings);

		if (direct_ok) {
			if (!previous_nss_ecm_direct_snapshot_valid) {
				direct_stats.snapshot_pending = true;
				add_string_unique(warnings, "nss_ecm_direct_snapshot_pending");
			} else if (now_ms < previous_nss_ecm_direct_snapshot_ms) {
				direct_stats.snapshot_pending = true;
				add_string_unique(warnings, "time_rollback");
				delta_ms = 0;
			}

			for (i = 0; i < direct_count; i++) {
				const struct conntrack_client_sample *previous;
				struct json_object *client;
				struct json_object *ips;
				bool counter_anomaly = false;
				uint64_t tx_bps = 0;
				uint64_t rx_bps = 0;
				size_t ip_index;
				size_t replace_idx = 0;

				previous = find_previous_nss_ecm_direct_sample(direct_current[i].identity_key);
				if (previous_nss_ecm_direct_snapshot_valid && previous) {
					tx_bps = delta_bps(direct_current[i].tx_bytes,
							   previous->tx_bytes, delta_ms,
							   &counter_anomaly);
					rx_bps = delta_bps(direct_current[i].rx_bytes,
							   previous->rx_bytes, delta_ms,
							   &counter_anomaly);
				}
				if (counter_anomaly)
					add_string_unique(warnings, "counter_anomaly");
				if (!direct_rate_has_data(tx_bps, rx_bps))
					continue;

				client = json_object_new_object();
				ips = json_object_new_array();
				for (ip_index = 0; ip_index < direct_current[i].ip_count; ip_index++)
					json_object_array_add(ips, json_object_new_string(direct_current[i].ips[ip_index]));

				json_object_object_add(client, "mac", json_object_new_string(direct_current[i].mac));
				json_object_object_add(client, "identity_key", json_object_new_string(direct_current[i].identity_key));
				json_object_object_add(client, "zone", json_object_new_string(direct_current[i].zone));
				json_object_object_add(client, "interface", json_object_new_string(direct_current[i].ifname));
				json_object_object_add(client, "ips", ips);
				{
					const char *ip_ptrs[MAX_CLIENT_IPS];
					const char *name;
					size_t k;
					for (k = 0; k < direct_current[i].ip_count; k++)
						ip_ptrs[k] = direct_current[i].ips[k];
					name = hostname_lookup(direct_current[i].mac, ip_ptrs,
							       direct_current[i].ip_count);
					json_object_object_add(client, "hostname",
					                       name ? json_object_new_string(name) : NULL);
				}
				json_object_object_add(client, "rx_bps", json_object_new_int64((int64_t)rx_bps));
				json_object_object_add(client, "tx_bps", json_object_new_int64((int64_t)tx_bps));
				json_object_object_add(client, "rx_bytes", json_object_new_int64((int64_t)direct_current[i].rx_bytes));
				json_object_object_add(client, "tx_bytes", json_object_new_int64((int64_t)direct_current[i].tx_bytes));
				json_object_object_add(client, "tcp_conns", json_object_new_int64((int64_t)direct_current[i].tcp_conns));
				json_object_object_add(client, "udp_conns", json_object_new_int64((int64_t)direct_current[i].udp_conns));
				json_object_object_add(client, "udp_dns_conns", json_object_new_int(0));
				json_object_object_add(client, "udp_other_conns", json_object_new_int64((int64_t)direct_current[i].udp_conns));
				json_object_object_add(client, "sample_ms", json_object_new_int64((int64_t)now_ms));
				json_object_object_add(client, "last_seen", json_object_new_int64((int64_t)direct_current[i].last_seen_ms));
				json_object_object_add(client, "collector_mode", json_object_new_string(NSS_ECM_DIRECT_SOURCE));
				json_object_object_add(client, "confidence", json_object_new_string("high"));
				json_object_object_add(client, "warnings", json_object_get(warnings));

				if (json_client_find_by_identity(sync_clients,
								 direct_current[i].identity_key,
								 &replace_idx)) {
					json_object_array_put_idx(sync_clients, replace_idx, client);
				} else {
					json_object_array_add(sync_clients, client);
				}
				direct_overlay_clients++;
			}

			memcpy(previous_nss_ecm_direct_samples, direct_current,
			       direct_count * sizeof(struct conntrack_client_sample));
			previous_nss_ecm_direct_sample_count = direct_count;
			previous_nss_ecm_direct_snapshot_ms = now_ms;
			previous_nss_ecm_direct_snapshot_valid = true;
		}
	}

	for (i = 0; i < json_object_array_length(sync_clients); i++) {
		struct json_object *client = json_object_array_get_idx(sync_clients, i);
		struct json_object *mode = NULL;
		const char *mode_name = NULL;

		if (client && json_object_object_get_ex(client, "collector_mode", &mode))
			mode_name = json_object_get_string(mode);
		if (mode_name && !strcmp(mode_name, "conntrack_ecm_sync"))
			sync_fallback_clients++;
		json_object_array_add(clients, json_object_get(client));
	}

	if (direct_attempted && (!direct_ok || direct_overlay_clients == 0))
		add_string_unique(warnings, "nss_direct_no_data");
	else if (direct_overlay_clients > 0 && sync_fallback_clients > 0)
		add_string_unique(warnings, "nss_direct_partial");
	if (sync_fallback_clients > 0)
		add_string_unique(warnings, "nss_sync_fallback");

	for (i = 0; i < json_object_array_length(warnings); i++) {
		struct json_object *entry = json_object_array_get_idx(warnings, i);
		size_t j;
		if (!entry)
			continue;
		for (j = 0; j < json_object_array_length(clients); j++) {
			struct json_object *client = json_object_array_get_idx(clients, j);
			struct json_object *client_warnings = NULL;
			if (client && json_object_object_get_ex(client, "warnings", &client_warnings))
				add_string_unique(client_warnings, json_object_get_string(entry));
		}
	}

	if (json_object_object_get_ex(sync_root, "tcp_conns_total", &value))
		json_object_object_add(root, "tcp_conns_total", json_object_get(value));
	if (json_object_object_get_ex(sync_root, "udp_conns_total", &value))
		json_object_object_add(root, "udp_conns_total", json_object_get(value));
	if (json_object_object_get_ex(sync_root, "udp_dns_conns_total", &value))
		json_object_object_add(root, "udp_dns_conns_total", json_object_get(value));
	if (json_object_object_get_ex(sync_root, "udp_other_conns_total", &value))
		json_object_object_add(root, "udp_other_conns_total", json_object_get(value));
	if (json_object_object_get_ex(sync_root, "conntrack_entries_seen", &value))
		json_object_object_add(root, "conntrack_entries_seen", json_object_get(value));
	if (json_object_object_get_ex(sync_root, "conntrack_entries_matched", &value))
		json_object_object_add(root, "conntrack_entries_matched", json_object_get(value));
	if (json_object_object_get_ex(sync_root, "conntrack_parse_errors", &value))
		json_object_object_add(root, "conntrack_parse_errors", json_object_get(value));
	if (json_object_object_get_ex(sync_root, "conn_source", &value))
		json_object_object_add(root, "conn_source", json_object_get(value));
	json_object_object_add(root, "conn_semantics", json_object_new_string("nss_sync_base_direct_overlay"));
	json_object_object_add(root, "nss_ecm_direct_flows_seen", json_object_new_int64((int64_t)direct_stats.entries_seen));
	json_object_object_add(root, "nss_ecm_direct_flows_matched", json_object_new_int64((int64_t)direct_stats.entries_matched));
	json_object_object_add(root, "nss_ecm_direct_parse_errors", json_object_new_int64((int64_t)direct_stats.malformed_lines));

	add_nss_stable_overlay_evidence(root, warnings, direct_attempted ? &direct_stats : NULL,
					direct_overlay_clients, sync_fallback_clients,
					json_object_array_length(clients));

	json_object_put(sync_root);
	return true;
}

/* ---------- coverage sliding window ---------- */

/* Sum byte counters from the latest collector snapshot selected by the
 * active source policy. Returns false when no usable snapshot
 * exists yet, in which case the caller must mark the sample invalid. */
static bool coverage_current_client_bytes(void *arg,
					  uint64_t *rx_out, uint64_t *tx_out)
{
	const struct runtime_probe *probe = arg;
	size_t i;
	uint64_t rx = 0, tx = 0;

	if (previous_nss_ecm_direct_snapshot_valid &&
	    previous_nss_ecm_direct_sample_count > 0 &&
	    nss_ecm_direct_preferred(probe) &&
	    !nss_conntrack_sync_stable_active(probe)) {
		for (i = 0; i < previous_nss_ecm_direct_sample_count; i++) {
			rx += previous_nss_ecm_direct_samples[i].rx_bytes;
			tx += previous_nss_ecm_direct_samples[i].tx_bytes;
		}
		*rx_out = rx;
		*tx_out = tx;
		return true;
	}
	if (previous_conntrack_snapshot_valid &&
	    previous_conntrack_sample_count > 0 &&
	    nss_conntrack_sync_stable_active(probe)) {
		for (i = 0; i < previous_conntrack_sample_count; i++) {
			rx += previous_conntrack_samples[i].rx_bytes;
			tx += previous_conntrack_samples[i].tx_bytes;
		}
		*rx_out = rx;
		*tx_out = tx;
		return true;
	}
	if (bpf_runtime_enabled && bpf_snapshot_totals(&bpf_cache, &rx, &tx)) {
		*rx_out = rx;
		*tx_out = tx;
		return true;
	}
	return false;
}

/* Sum LAN-role iface byte counters straight from /sys/class/net. Uses
 * the same source as interfaces_method so the numerator and denominator
 * live in the same observation domain. */
static bool coverage_current_iface_bytes(void *arg, uint64_t *rx_out, uint64_t *tx_out)
{
	size_t i;
	uint64_t rx = 0, tx = 0;
	bool any_ok = false;

	(void)arg;

	for (i = 0; i < bpf_attach_ifname_count; i++) {
		const char *name = bpf_attach_ifnames[i];
		char path[PATH_MAX];
		char buf[64];
		FILE *fp;
		uint64_t v;

		snprintf(path, sizeof(path), "/sys/class/net/%s/statistics/rx_bytes", name);
		fp = fopen(path, "r");
		if (!fp)
			continue;
		if (fgets(buf, sizeof(buf), fp))
			rx += strtoull(buf, NULL, 10);
		fclose(fp);

		snprintf(path, sizeof(path), "/sys/class/net/%s/statistics/tx_bytes", name);
		fp = fopen(path, "r");
		if (!fp)
			continue;
		if (fgets(buf, sizeof(buf), fp))
			v = strtoull(buf, NULL, 10);
		else
			v = 0;
		tx += v;
		fclose(fp);
		any_ok = true;
	}

	if (!any_ok)
		return false;

	*rx_out = rx;
	*tx_out = tx;
	return true;
}

static int send_json_reply(struct ubus_context *ubus, struct ubus_request_data *req,
			   struct json_object *root);

static int overview_method(struct ubus_context *ubus, struct ubus_object *obj,
			   struct ubus_request_data *req, const char *method,
			   struct blob_attr *msg)
{
	struct lanspeed_overview_config config = overview_config();
	struct json_object *root;

	(void)obj;
	(void)method;
	(void)msg;

	root = lanspeed_overview_to_json(&overview_ring, &config);

	return send_json_reply(ubus, req, root);
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
	load_cached_runtime_probe(&probe);
	if (bpf_runtime_refresh_attach_policy(&probe)) {
		free_runtime_probe(&probe);
		init_runtime_probe(&probe);
		load_cached_runtime_probe(&probe);
	}
	mode = probe_mode(&probe);
	if (strcmp(mode, "Full"))
		add_warning(&probe, "live_metrics_unavailable");
	finish_probe_evidence(&probe, "status");

	json_object_object_add(root, "mode", json_object_new_string(mode));
	json_object_object_add(root, "confidence", json_object_new_string(probe_confidence(&probe, mode)));
	json_object_object_add(root, "warnings", runtime_probe_take_json(&probe.warnings));
	json_object_object_add(root, "evidence", runtime_probe_take_json(&probe.evidence));
	json_object_object_add(root, "refresh_interval_ms", json_object_new_int(refresh_interval_ms));
	json_object_object_add(root, "active_client_window_ms",
			       json_object_new_int64((int64_t)active_client_window_ms));
	json_object_object_add(root, "active_client_min_bps",
			       json_object_new_int64((int64_t)active_client_min_bps));
	json_object_object_add(root, "overview_window_samples",
			       json_object_new_int(overview_window_samples));
	json_object_object_add(root, "collector_mode",
			       json_object_new_string(collector_mode_config_name()));
	json_object_object_add(root, "rate_collector_mode",
			       json_object_new_string(rate_collector_mode_config_name()));
	json_object_object_add(root, "conn_collector_mode",
			       json_object_new_string(conn_collector_mode_config_name()));
	json_object_object_add(root, "version", json_object_new_string(LANSPEED_FULL_VERSION));
	add_capabilities_from_values(root, enable_bpf && bpf_primary_active(&probe) &&
				     !nss_conntrack_sync_stable_active(&probe),
				     enable_conntrack_fallback,
				     nss_conntrack_sync_stable_active(&probe) ||
				     nss_ecm_direct_preferred(&probe) ||
				     bpf_primary_active(&probe), &probe);
	{
		struct lanspeed_coverage_readers readers = {
			.read_iface_bytes = coverage_current_iface_bytes,
			.read_client_bytes = coverage_current_client_bytes,
			.arg = &probe
		};
		struct lanspeed_coverage_config coverage_config = {
			.supported = bpf_runtime_enabled ||
				nss_ecm_direct_preferred(&probe) ||
				nss_conntrack_sync_stable_active(&probe)
		};

		lanspeed_coverage_push_sample(&coverage_ring, monotonic_time_ms(),
					      &readers);
		lanspeed_coverage_add_json(&coverage_ring, root,
					   &coverage_config);
	}
	free_runtime_probe(&probe);

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
	uint32_t udp_dns_total = 0;
	uint32_t udp_other_total = 0;

	read_ok = read_conntrack_snapshot_mode(conn_samples, &conn_count,
					       max_samples, now_ms,
					       discard_warnings, &conn_stats,
					       conn_collector_mode);
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
			/* Connection counts are a current-table property.
			 * Keep BPF for byte rates, but always publish the
			 * conntrack view when procfs is readable so daed/NSS
			 * hook order does not leave stale BPF conn counts in UI. */
			json_object_object_add(client, "tcp_conns",
					       json_object_new_int64((int64_t)cs->tcp_conns));
			json_object_object_add(client, "udp_conns",
					       json_object_new_int64((int64_t)cs->udp_conns));
			json_object_object_add(client, "udp_dns_conns",
					       json_object_new_int64((int64_t)cs->udp_dns_conns));
			json_object_object_add(client, "udp_other_conns",
					       json_object_new_int64((int64_t)cs->udp_other_conns));
			tcp_total += cs->tcp_conns;
			udp_total += cs->udp_conns;
			udp_dns_total += cs->udp_dns_conns;
			udp_other_total += cs->udp_other_conns;
		} else {
			json_object_object_add(client, "tcp_conns", json_object_new_int(0));
			json_object_object_add(client, "udp_conns", json_object_new_int(0));
			json_object_object_add(client, "udp_dns_conns", json_object_new_int(0));
			json_object_object_add(client, "udp_other_conns", json_object_new_int(0));
		}
	}

	/* Add top-level connection count summary and diagnostics */
	json_object_object_add(root, "tcp_conns_total",
			       json_object_new_int((int)tcp_total));
	json_object_object_add(root, "udp_conns_total",
			       json_object_new_int((int)udp_total));
	json_object_object_add(root, "udp_dns_conns_total",
			       json_object_new_int((int)udp_dns_total));
	json_object_object_add(root, "udp_other_conns_total",
			       json_object_new_int((int)udp_other_total));
	json_object_object_add(root, "conntrack_entries_seen",
			       json_object_new_int((int)conn_stats.entries_seen));
	json_object_object_add(root, "conntrack_entries_matched",
			       json_object_new_int((int)conn_stats.entries_matched));
	json_object_object_add(root, "conntrack_parse_errors",
			       json_object_new_int((int)conn_stats.malformed_lines));
	json_object_object_add(root, "conn_source",
			       json_object_new_string(conntrack_stats_source(&conn_stats)));
	json_object_object_add(root, "conn_collector_mode",
			       json_object_new_string(conn_collector_mode_config_name()));
	json_object_object_add(root, "conn_semantics",
			       json_object_new_string("conntrack_current_tcp_established_assured_udp_tracked_dns_split"));
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
		load_cached_runtime_probe(&probe);
		if (bpf_runtime_refresh_attach_policy(&probe)) {
			bpf_collect_samples();
			free_runtime_probe(&probe);
			init_runtime_probe(&probe);
			load_cached_runtime_probe(&probe);
		}
		if (nss_conntrack_sync_stable_active(&probe)) {
			if (collect_nss_stable_clients(root, clients, &probe)) {
				merge_conntrack_conn_counts(root, clients);
			} else if (!collect_conntrack_procfs_clients(root, clients, &probe) &&
			    collect_bpf_clients(root, clients, &probe)) {
				merge_conntrack_conn_counts(root, clients);
			}
		} else if (nss_daed_should_prefer_bpf(&probe)) {
			if (collect_bpf_clients(root, clients, &probe))
				merge_conntrack_conn_counts(root, clients);
		} else if (nss_conntrack_sync_preferred(&probe)) {
			if (!collect_conntrack_procfs_clients(root, clients, &probe) &&
			    collect_bpf_clients(root, clients, &probe)) {
				/* BPF is only a slow-path fallback under NSS sync,
				 * but its connection counts can still be topped up
				 * from conntrack when available. */
				merge_conntrack_conn_counts(root, clients);
			}
		} else if (collect_bpf_clients(root, clients, &probe)) {
			/* BPF provides rate data; additionally scan conntrack
			 * for connection counts only (tcp_conns/udp_conns).
			 * This does NOT overwrite BPF rate fields. */
			merge_conntrack_conn_counts(root, clients);
		}
		free_runtime_probe(&probe);
	}

	add_clients_identity_evidence(root);
	{
		struct lanspeed_overview_config config = overview_config();
		lanspeed_overview_push_from_clients(&overview_ring, root, clients,
						    monotonic_time_ms(),
						    &config);
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
	runtime_probe_cache_store(&probe);
	if (bpf_runtime_refresh_attach_policy(&probe)) {
		free_runtime_probe(&probe);
		init_runtime_probe(&probe);
		inspect_runtime(&probe);
		runtime_probe_cache_store(&probe);
	}
	mode = probe_mode(&probe);
	if (strcmp(mode, "Full"))
		add_warning(&probe, "live_metrics_unavailable");
	finish_probe_evidence(&probe, "health");

	json_object_object_add(root, "mode", json_object_new_string(mode));
	json_object_object_add(root, "confidence", json_object_new_string(probe_confidence(&probe, mode)));
	add_capabilities_from_values(root, enable_bpf && bpf_primary_active(&probe) &&
				     !nss_conntrack_sync_stable_active(&probe),
				     enable_conntrack_fallback,
				     nss_conntrack_sync_stable_active(&probe) ||
				     nss_ecm_direct_preferred(&probe) ||
				     bpf_primary_active(&probe), &probe);
	json_object_object_add(root, "conflicts", runtime_probe_take_json(&probe.conflicts));
	json_object_object_add(root, "warnings", runtime_probe_take_json(&probe.warnings));
	json_object_object_add(root, "evidence", runtime_probe_take_json(&probe.evidence));
	free_runtime_probe(&probe);

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
	/* Proxy/uplink-only identity sources must stay observe-only.
	 * This keeps daed's dae0/dae0peer out of the collect path. */
	if (ifname_is_excluded_identity_source(name))
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
	UBUS_METHOD_NOARG("overview", overview_method),
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
	/* Only recommended LAN edges may carry the BPF collector.
	 * Proxy/uplink-only and mirror interfaces stay observe-only. */
	if (!sysdevice_is_recommended_lan(name))
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
	struct lanspeed_runtime_config config;

	lanspeed_config_load_uci(&config, uci);
	refresh_interval_ms = config.refresh_interval_ms;
	max_clients = config.max_clients;
	active_client_window_ms = config.active_client_window_ms;
	active_client_min_bps = config.active_client_min_bps;
	overview_window_samples = config.overview_window_samples;
	enable_bpf = config.enable_bpf;
	enable_conntrack_fallback = config.enable_conntrack_fallback;
	refresh_interval_clamped = config.refresh_interval_clamped;
	active_client_window_clamped = config.active_client_window_clamped;
	active_client_min_bps_clamped = config.active_client_min_bps_clamped;
	overview_window_samples_clamped = config.overview_window_samples_clamped;
	rate_collector_mode = config.rate_collector_mode;
	conn_collector_mode = config.conn_collector_mode;

	if (!uci)
		return;

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

	if (!enable_bpf || !rate_collector_mode_allows_bpf())
		return;

	env_path = getenv("LANSPEED_BPF_OBJECT_PATH");
	object_path = (env_path && *env_path) ? env_path : LANSPEED_BPF_OBJECT_PATH;
	snprintf(bpf_object_runtime_path, sizeof(bpf_object_runtime_path),
		 "%s", object_path);

	if (!lanspeed_bpf_init(object_path))
		return;

	{
		struct runtime_probe probe;

		init_runtime_probe(&probe);
		inspect_command_capabilities(&probe);
		inspect_tc(&probe);
		runtime_probe_cache_store(&probe);
		bpf_runtime_early_passthrough = dae_tc_preempts_bpf_ingress(&probe);
		free_runtime_probe(&probe);
	}

	for (i = 0; i < bpf_attach_ifname_count; i++) {
		if (lanspeed_bpf_attach_iface_mode(bpf_attach_ifnames[i],
						   bpf_runtime_early_passthrough) == 0)
			attached_ok++;
	}

	if (attached_ok == 0) {
		lanspeed_bpf_shutdown();
		return;
	}

	bpf_runtime_enabled = true;
	bpf_runtime_recover_if_needed("initial_tc_filter_check");
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
	bpf_runtime_early_passthrough = false;
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
