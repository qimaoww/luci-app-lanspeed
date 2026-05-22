/* SPDX-License-Identifier: Apache-2.0 */
#ifndef LANSPEED_BPF_COLLECTOR_H
#define LANSPEED_BPF_COLLECTOR_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <json-c/json.h>

#include "lanspeed_config.h"
#include "lanspeed_identity.h"

#define BPF_MAX_CLIENT_IPS 4

struct bpf_client_sample {
	char mac[MAC_STR_LEN];
	char identity_key[IDENTITY_KEY_STR_LEN];
	char zone[ZONE_STR_LEN];
	char ifname[IFNAME_STR_LEN];
	char ips[BPF_MAX_CLIENT_IPS][IP_STR_LEN];
	size_t ip_count;
	uint64_t tx_bytes;
	uint64_t rx_bytes;
	uint64_t last_seen_ms;
	uint32_t tcp_conns;
	uint32_t udp_conns;
};

struct bpf_rate_sample {
	char mac[MAC_STR_LEN];
	char identity_key[IDENTITY_KEY_STR_LEN];
	char zone[ZONE_STR_LEN];
	char ifname[IFNAME_STR_LEN];
	char ips[BPF_MAX_CLIENT_IPS][IP_STR_LEN];
	size_t ip_count;
	uint64_t tx_bytes;
	uint64_t rx_bytes;
	uint64_t tx_bps;
	uint64_t rx_bps;
	uint64_t sample_ms;
	uint64_t last_seen_ms;
	uint32_t bpf_approx_tcp_tuples;
	uint32_t bpf_approx_udp_tuples;
	bool counter_anomaly;
};

struct bpf_snapshot_cache {
	struct bpf_client_sample current[DEFAULT_MAX_CLIENTS];
	size_t current_count;
	uint64_t current_snapshot_ms;
	struct bpf_client_sample previous[DEFAULT_MAX_CLIENTS];
	size_t previous_count;
	uint64_t previous_snapshot_ms;
	bool previous_valid;
};

void bpf_snapshot_cache_reset(struct bpf_snapshot_cache *cache);
bool bpf_collect_snapshot(struct bpf_snapshot_cache *cache, size_t max_clients,
			  uint64_t now_ms, struct json_object *warnings);
size_t bpf_build_rate_samples(const struct bpf_snapshot_cache *cache,
			      struct bpf_rate_sample *out, size_t max_out,
			      uint64_t *delta_ms_out);
bool bpf_snapshot_totals(const struct bpf_snapshot_cache *cache,
			 uint64_t *rx_out, uint64_t *tx_out);

#endif
