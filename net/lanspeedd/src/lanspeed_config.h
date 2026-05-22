/* SPDX-License-Identifier: Apache-2.0 */
#ifndef LANSPEED_CONFIG_H
#define LANSPEED_CONFIG_H

#include <stdbool.h>
#include <stdint.h>

struct uci_context;

#define DEFAULT_REFRESH_INTERVAL_MS 1000
#define MIN_REFRESH_INTERVAL_MS 500
#define DEFAULT_MAX_CLIENTS 2048
#define DEFAULT_ACTIVE_CLIENT_WINDOW_MS 10000ULL
#define MIN_ACTIVE_CLIENT_WINDOW_MS 1000ULL
#define DEFAULT_ACTIVE_CLIENT_MIN_BPS 1ULL
#define LANSPEED_OVERVIEW_WINDOW 240
#define DEFAULT_OVERVIEW_WINDOW_SAMPLES LANSPEED_OVERVIEW_WINDOW
#define MIN_OVERVIEW_WINDOW_SAMPLES 2

#define CONNTRACK_NETLINK_SOURCE "conntrack_netlink"
#define CONNTRACK_PROCFS_SOURCE "conntrack_procfs"
#define NSS_ECM_DIRECT_SOURCE "nss_ecm_direct"

enum collector_mode_setting {
	COLLECTOR_MODE_AUTO,
	COLLECTOR_MODE_BPF,
	COLLECTOR_MODE_NSS_ECM_DIRECT,
	COLLECTOR_MODE_NSS_CONNTRACK_SYNC,
	COLLECTOR_MODE_CONNTRACK_NETLINK,
	COLLECTOR_MODE_CONNTRACK_PROCFS
};

struct lanspeed_runtime_config {
	int refresh_interval_ms;
	int max_clients;
	uint64_t active_client_window_ms;
	uint64_t active_client_min_bps;
	int overview_window_samples;
	bool enable_bpf;
	bool enable_conntrack_fallback;
	bool refresh_interval_clamped;
	bool active_client_window_clamped;
	bool active_client_min_bps_clamped;
	bool overview_window_samples_clamped;
	enum collector_mode_setting rate_collector_mode;
	enum collector_mode_setting conn_collector_mode;
};

void lanspeed_config_defaults(struct lanspeed_runtime_config *config);
void lanspeed_config_load(struct lanspeed_runtime_config *config);
void lanspeed_config_load_uci(struct lanspeed_runtime_config *config,
			      struct uci_context *uci);

const char *collector_mode_name(enum collector_mode_setting mode);
enum collector_mode_setting parse_rate_collector_mode(const char *value,
						      enum collector_mode_setting fallback);
enum collector_mode_setting parse_conn_collector_mode(const char *value,
						      enum collector_mode_setting fallback);
void lanspeed_config_apply_legacy_collector_mode(struct lanspeed_runtime_config *config,
						 const char *value);

#endif
