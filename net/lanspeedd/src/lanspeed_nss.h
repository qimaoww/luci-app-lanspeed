/* SPDX-License-Identifier: Apache-2.0 */
#ifndef LANSPEED_NSS_H
#define LANSPEED_NSS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <limits.h>

#include <json-c/json.h>

#include "lanspeed_conntrack.h"

#define NSS_ECM_STATE_DEBUGFS_DIR "/sys/kernel/debug/ecm/ecm_state"
#define NSS_ECM_STATE_DEV_MAJOR_PATH NSS_ECM_STATE_DEBUGFS_DIR "/state_dev_major"
#define NSS_ECM_STATE_OUTPUT_MASK_PATH NSS_ECM_STATE_DEBUGFS_DIR "/state_file_output_mask"
#define NSS_ECM_STATE_DEV_PATH "/dev/ecm_state"
#define NSS_ECM_STATE_TMP_DEV_PATH "/dev/lanspeed-ecm-state"
#define NSS_ECM_STATE_LINE_MAX 1024

struct nss_ecm_direct_stats {
	char source_path[PATH_MAX];
	bool state_attempted;
	bool state_read;
	bool snapshot_pending;
	int state_errno;
	unsigned int state_major;
	size_t entries_seen;
	size_t entries_matched;
	size_t skipped_no_arp;
	size_t no_lan_flows;
	size_t both_lan_flows;
	size_t src_lan_flows;
	size_t dst_lan_flows;
	size_t ipv4_lan_flows;
	size_t ipv6_lan_flows;
	size_t malformed_lines;
	size_t current_clients;
	size_t emitted_clients;
};

bool nss_ecm_state_open(FILE **file, char *source_path,
			size_t source_path_size, int *err_out,
			unsigned int *major_out);
bool read_nss_ecm_direct_snapshot(struct conntrack_client_sample *samples,
				  size_t *sample_count, size_t max_samples,
				  uint64_t now_ms, struct json_object *warnings,
				  struct nss_ecm_direct_stats *stats);

#endif
