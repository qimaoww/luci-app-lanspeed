/* SPDX-License-Identifier: Apache-2.0 */
#include <net/if.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

#include <libubox/utils.h>

#include "lanspeed_bpf.h"
#include "lanspeed_bpf_collector.h"

static uint64_t monotonic_ns_to_ms(uint64_t ns)
{
	return ns / 1000000ULL;
}

static uint64_t bpf_delta_bps(uint64_t current, uint64_t previous,
			      uint64_t delta_ms, bool *counter_anomaly)
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

	for (i = 0; i < arp_count && sample->ip_count < BPF_MAX_CLIENT_IPS; i++) {
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

static const struct bpf_client_sample *bpf_find_previous_sample(
	const struct bpf_snapshot_cache *cache, const char *identity_key)
{
	size_t i;

	if (!cache || !identity_key)
		return NULL;

	for (i = 0; i < cache->previous_count; i++) {
		if (!strcmp(cache->previous[i].identity_key, identity_key))
			return &cache->previous[i];
	}

	return NULL;
}

void bpf_snapshot_cache_reset(struct bpf_snapshot_cache *cache)
{
	if (!cache)
		return;
	cache->current_count = 0;
	cache->current_snapshot_ms = 0;
	cache->previous_count = 0;
	cache->previous_snapshot_ms = 0;
	cache->previous_valid = false;
}

bool bpf_collect_snapshot(struct bpf_snapshot_cache *cache, size_t max_clients,
			  uint64_t now_ms, struct json_object *warnings)
{
	struct lanspeed_bpf_sample raw[DEFAULT_MAX_CLIENTS * 2];
	struct arp_entry arp_entries[DEFAULT_MAX_CLIENTS];
	size_t raw_count = 0;
	size_t arp_count;
	size_t max_folded = max_clients > 0 && max_clients < DEFAULT_MAX_CLIENTS ?
			    max_clients : DEFAULT_MAX_CLIENTS;
	size_t i;

	if (!cache)
		return false;

	if (lanspeed_bpf_read_samples(raw, ARRAY_SIZE(raw), &raw_count) != 0)
		return false;

	memcpy(cache->previous, cache->current,
	       cache->current_count * sizeof(cache->current[0]));
	cache->previous_count = cache->current_count;
	cache->previous_snapshot_ms = cache->current_snapshot_ms;
	cache->previous_valid = cache->previous_snapshot_ms > 0;

	cache->current_count = 0;
	cache->current_snapshot_ms = now_ms;

	arp_count = load_lan_identity_table(arp_entries, ARRAY_SIZE(arp_entries),
					    warnings);

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

		sample = bpf_find_or_insert_client(cache->current,
						   &cache->current_count,
						   max_folded, mac_str, zone,
						   ifname_buf, identity_key,
						   arp_entries, arp_count);
		if (!sample)
			break;

		if (raw[i].direction == LANSPEED_BPF_DIR_TX) {
			sample->tx_bytes += raw[i].bytes;
			sample->tcp_conns = raw[i].tcp_conns;
			sample->udp_conns = raw[i].udp_conns;
		} else if (raw[i].direction == LANSPEED_BPF_DIR_RX) {
			sample->rx_bytes += raw[i].bytes;
		}
		if (raw[i].last_seen_ns) {
			uint64_t raw_last_seen_ms = monotonic_ns_to_ms(raw[i].last_seen_ns);
			if (raw_last_seen_ms > sample->last_seen_ms)
				sample->last_seen_ms = raw_last_seen_ms;
		} else if (now_ms > sample->last_seen_ms) {
			sample->last_seen_ms = now_ms;
		}
	}

	return true;
}

size_t bpf_build_rate_samples(const struct bpf_snapshot_cache *cache,
			      struct bpf_rate_sample *out, size_t max_out,
			      uint64_t *delta_ms_out)
{
	uint64_t delta_ms;
	size_t emitted = 0;
	size_t i;

	if (delta_ms_out)
		*delta_ms_out = 0;
	if (!cache || !out || !cache->previous_valid || cache->current_count == 0)
		return 0;
	if (cache->current_snapshot_ms <= cache->previous_snapshot_ms)
		return 0;

	delta_ms = cache->current_snapshot_ms - cache->previous_snapshot_ms;
	if (delta_ms == 0)
		return 0;
	if (delta_ms_out)
		*delta_ms_out = delta_ms;

	for (i = 0; i < cache->current_count && emitted < max_out; i++) {
		const struct bpf_client_sample *cur = &cache->current[i];
		const struct bpf_client_sample *prev;
		struct bpf_rate_sample *rate = &out[emitted];
		bool counter_anomaly = false;

		memset(rate, 0, sizeof(*rate));
		snprintf(rate->mac, sizeof(rate->mac), "%s", cur->mac);
		snprintf(rate->identity_key, sizeof(rate->identity_key), "%s", cur->identity_key);
		snprintf(rate->zone, sizeof(rate->zone), "%s", cur->zone);
		snprintf(rate->ifname, sizeof(rate->ifname), "%s", cur->ifname);
		memcpy(rate->ips, cur->ips, sizeof(rate->ips));
		rate->ip_count = cur->ip_count;
		rate->tx_bytes = cur->tx_bytes;
		rate->rx_bytes = cur->rx_bytes;
		rate->sample_ms = cache->current_snapshot_ms;
		rate->last_seen_ms = cur->last_seen_ms;
		rate->bpf_approx_tcp_tuples = cur->tcp_conns;
		rate->bpf_approx_udp_tuples = cur->udp_conns;

		prev = bpf_find_previous_sample(cache, cur->identity_key);
		if (prev) {
			rate->tx_bps = bpf_delta_bps(cur->tx_bytes, prev->tx_bytes,
						     delta_ms, &counter_anomaly);
			rate->rx_bps = bpf_delta_bps(cur->rx_bytes, prev->rx_bytes,
						     delta_ms, &counter_anomaly);
		}
		rate->counter_anomaly = counter_anomaly;
		emitted++;
	}

	return emitted;
}

bool bpf_snapshot_totals(const struct bpf_snapshot_cache *cache,
			 uint64_t *rx_out, uint64_t *tx_out)
{
	size_t i;
	uint64_t rx = 0;
	uint64_t tx = 0;

	if (!cache || cache->current_count == 0)
		return false;

	for (i = 0; i < cache->current_count; i++) {
		rx += cache->current[i].rx_bytes;
		tx += cache->current[i].tx_bytes;
	}

	if (rx_out)
		*rx_out = rx;
	if (tx_out)
		*tx_out = tx;
	return true;
}
