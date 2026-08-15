// SPDX-License-Identifier: GPL-2.0-only

#include <linux/module.h>
#include <linux/netlink.h>
#include <net/genetlink.h>

#include "lanspeed_nss_control.h"

#define LANSPEED_GENL_MAX_CONFIG 4095

static struct genl_family lanspeed_genl_family;

static const struct nla_policy lanspeed_genl_policy[LANSPEED_NSS_A_MAX + 1] = {
	[LANSPEED_NSS_A_ABI_VERSION] = { .type = NLA_U32 },
	[LANSPEED_NSS_A_IFB_NAME] = {
		.type = NLA_NUL_STRING,
		.len = IFNAMSIZ - 1,
	},
	[LANSPEED_NSS_A_EDGE_NAME] = {
		.type = NLA_NUL_STRING,
		.len = IFNAMSIZ - 1,
	},
	[LANSPEED_NSS_A_CONFIG] = {
		.type = NLA_NUL_STRING,
		.len = LANSPEED_GENL_MAX_CONFIG,
	},
};

static int lanspeed_genl_reply_start(struct sk_buff **skb,
					struct genl_info *info,
					void **header,
					u8 command)
{
	*skb = genlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!*skb)
		return -ENOMEM;
	*header = genlmsg_put_reply(*skb, info, &lanspeed_genl_family, 0,
					command);
	if (!*header) {
		nlmsg_free(*skb);
		*skb = NULL;
		return -EMSGSIZE;
	}
	return 0;
}

static int lanspeed_genl_reply_finish(struct sk_buff *skb,
				      struct genl_info *info,
				      void *header)
{
	genlmsg_end(skb, header);
	return genlmsg_reply(skb, info);
}

static int lanspeed_genl_get_caps(struct sk_buff *skb, struct genl_info *info)
{
	struct sk_buff *reply;
	void *header;
	int error;

	error = lanspeed_genl_reply_start(&reply, info, &header,
					  LANSPEED_NSS_CMD_GET_CAPS);
	if (error)
		return error;
	if (nla_put_u32(reply, LANSPEED_NSS_A_ABI_VERSION,
			LANSPEED_NSS_GENL_VERSION) ||
	    nla_put_u32(reply, LANSPEED_NSS_A_FEATURE_BITS,
			LANSPEED_NSS_FEATURE_IGS |
			LANSPEED_NSS_FEATURE_WIFI_PEER |
			LANSPEED_NSS_FEATURE_IGS_STATS |
			LANSPEED_NSS_FEATURE_PEER_QUERY |
			LANSPEED_NSS_FEATURE_RCU_TAGS |
			LANSPEED_NSS_FEATURE_TRUSTED_INGRESS |
			LANSPEED_NSS_FEATURE_IGS_CADENCE) ||
	    nla_put_u32(reply, LANSPEED_NSS_A_MAX_IGS, LANSPEED_MAX_IGS) ||
	    nla_put_u32(reply, LANSPEED_NSS_A_MAX_PEERS,
			LANSPEED_MAX_WIFI_PEERS) ||
	    nla_put_u32(reply, LANSPEED_NSS_A_MAX_CLIENT_TAGS,
			LANSPEED_MAX_CLIENT_TAGS) ||
	    nla_put_u8(reply, LANSPEED_NSS_A_SUPPORTS_WIFI_PEER, 1) ||
	    nla_put_u8(reply, LANSPEED_NSS_A_SUPPORTS_IGS_STATS, 1) ||
	    nla_put_u8(reply, LANSPEED_NSS_A_SUPPORTS_PEER_QUERY, 1)) {
		genlmsg_cancel(reply, header);
		return -EMSGSIZE;
	}
	return lanspeed_genl_reply_finish(reply, info, header);
}

static int lanspeed_genl_get_state(struct sk_buff *skb, struct genl_info *info)
{
	struct lanspeed_igs_entry *entry;
	struct sk_buff *reply;
	void *header;
	u32 staged = 0;
	u32 published = 0;
	u32 degraded = 0;
	int error;

	mutex_lock(&lanspeed_igs_lock);
	list_for_each_entry(entry, &lanspeed_igs_entries, list) {
		switch (entry->state) {
		case LANSPEED_IGS_STAGED:
			staged++;
			break;
		case LANSPEED_IGS_PUBLISHED:
			published++;
			break;
		case LANSPEED_IGS_DEGRADED:
			degraded++;
			break;
		}
	}
	mutex_unlock(&lanspeed_igs_lock);

	error = lanspeed_genl_reply_start(&reply, info, &header,
					  LANSPEED_NSS_CMD_GET_STATE);
	if (error)
		return error;
	if (nla_put_u32(reply, LANSPEED_NSS_A_IGS_STAGED, staged) ||
	    nla_put_u32(reply, LANSPEED_NSS_A_IGS_PUBLISHED, published) ||
	    nla_put_u32(reply, LANSPEED_NSS_A_IGS_DEGRADED, degraded)) {
		genlmsg_cancel(reply, header);
		return -EMSGSIZE;
	}
	return lanspeed_genl_reply_finish(reply, info, header);
}

static int lanspeed_genl_put_snapshot(struct sk_buff *reply,
				      const struct lanspeed_telemetry_snapshot *value)
{
	return nla_put_u64_64bit(reply, LANSPEED_NSS_A_CONTROL_GENERATION,
			value->control_generation, LANSPEED_NSS_A_UNSPEC) ||
	       nla_put_u64_64bit(reply, LANSPEED_NSS_A_HARDWARE_GENERATION,
			value->hardware_generation, LANSPEED_NSS_A_UNSPEC) ||
	       nla_put_u64_64bit(reply, LANSPEED_NSS_A_PEER_GENERATION,
			value->peer_generation, LANSPEED_NSS_A_UNSPEC) ||
	       nla_put_u64_64bit(reply, LANSPEED_NSS_A_PEER_REASSERT_COUNT,
			value->peer_reassert_count, LANSPEED_NSS_A_UNSPEC) ||
	       nla_put_u64_64bit(reply, LANSPEED_NSS_A_IGS_SYNC_COUNT,
			value->igs_sync_count, LANSPEED_NSS_A_UNSPEC) ||
	       nla_put_u64_64bit(reply, LANSPEED_NSS_A_IGS_LAST_SYNC_NS,
			value->igs_last_sync_ns, LANSPEED_NSS_A_UNSPEC) ||
	       nla_put_u64_64bit(reply, LANSPEED_NSS_A_IGS_BYTES,
			value->igs_bytes, LANSPEED_NSS_A_UNSPEC) ||
	       nla_put_u64_64bit(reply, LANSPEED_NSS_A_IGS_PACKETS,
			value->igs_packets, LANSPEED_NSS_A_UNSPEC) ||
	       nla_put_u64_64bit(reply, LANSPEED_NSS_A_IGS_DROPS,
			value->igs_drops, LANSPEED_NSS_A_UNSPEC) ||
	       nla_put_u64_64bit(reply, LANSPEED_NSS_A_IGS_CADENCE_SAMPLES,
			value->igs_cadence_samples, LANSPEED_NSS_A_UNSPEC) ||
	       nla_put_u64_64bit(reply, LANSPEED_NSS_A_IGS_CADENCE_LAST_NS,
			value->igs_cadence_last_ns, LANSPEED_NSS_A_UNSPEC) ||
	       nla_put_u64_64bit(reply, LANSPEED_NSS_A_IGS_CADENCE_MIN_NS,
			value->igs_cadence_min_ns, LANSPEED_NSS_A_UNSPEC) ||
	       nla_put_u64_64bit(reply, LANSPEED_NSS_A_IGS_CADENCE_MAX_NS,
			value->igs_cadence_max_ns, LANSPEED_NSS_A_UNSPEC) ||
	       nla_put_u32(reply, LANSPEED_NSS_A_IGS_ACTIVE_NODES,
			   value->igs_active_nodes) ||
	       nla_put_u64_64bit(reply, LANSPEED_NSS_A_ACK_LATENCY_LAST_NS,
			value->ack_latency_last_ns, LANSPEED_NSS_A_UNSPEC) ||
	       nla_put_u64_64bit(reply, LANSPEED_NSS_A_ACK_LATENCY_MAX_NS,
			value->ack_latency_max_ns, LANSPEED_NSS_A_UNSPEC) ||
	       nla_put_u64_64bit(reply, LANSPEED_NSS_A_ACK_RECEIVED,
			value->ack_received, LANSPEED_NSS_A_UNSPEC) ||
	       nla_put_u64_64bit(reply, LANSPEED_NSS_A_ACK_TIMEOUT,
			value->ack_timeout, LANSPEED_NSS_A_UNSPEC) ||
	       nla_put_u64_64bit(reply, LANSPEED_NSS_A_ACK_LATE,
			value->ack_late, LANSPEED_NSS_A_UNSPEC);
}

static int lanspeed_genl_get_stats(struct sk_buff *skb, struct genl_info *info)
{
	struct lanspeed_telemetry_snapshot value;
	struct sk_buff *reply;
	void *header;
	int error;

	lanspeed_telemetry_snapshot(&value);
	error = lanspeed_genl_reply_start(&reply, info, &header,
					  LANSPEED_NSS_CMD_GET_STATS);
	if (error)
		return error;
	if (lanspeed_genl_put_snapshot(reply, &value)) {
		genlmsg_cancel(reply, header);
		return -EMSGSIZE;
	}
	return lanspeed_genl_reply_finish(reply, info, header);
}

static int lanspeed_genl_get_health(struct sk_buff *skb, struct genl_info *info)
{
	struct lanspeed_telemetry_snapshot value;
	struct sk_buff *reply;
	void *header;
	int error;

	lanspeed_telemetry_snapshot(&value);
	error = lanspeed_genl_reply_start(&reply, info, &header,
					  LANSPEED_NSS_CMD_GET_HEALTH);
	if (error)
		return error;
	if (nla_put_u8(reply, LANSPEED_NSS_A_HEALTHY,
			value.ack_timeout == 0 && value.ack_late == 0) ||
	    nla_put_u64_64bit(reply, LANSPEED_NSS_A_CONTROL_GENERATION,
			value.control_generation, LANSPEED_NSS_A_UNSPEC) ||
	    nla_put_u64_64bit(reply, LANSPEED_NSS_A_HARDWARE_GENERATION,
			value.hardware_generation, LANSPEED_NSS_A_UNSPEC)) {
		genlmsg_cancel(reply, header);
		return -EMSGSIZE;
	}
	return lanspeed_genl_reply_finish(reply, info, header);
}

static int lanspeed_genl_require_string(struct genl_info *info, u16 attr,
					const char **value)
{
	if (!info->attrs[attr])
		return -EINVAL;
	*value = nla_data(info->attrs[attr]);
	return 0;
}

static int lanspeed_genl_igs_stage(struct sk_buff *skb, struct genl_info *info)
{
	const char *ifb;
	int error = lanspeed_genl_require_string(info, LANSPEED_NSS_A_IFB_NAME,
						 &ifb);

	return error ? error : lanspeed_igs_stage(ifb);
}

static int lanspeed_genl_igs_publish(struct sk_buff *skb,
					 struct genl_info *info)
{
	char value[IFNAMSIZ * 2 + 2];
	const char *ifb;
	const char *edge;
	int error;

	error = lanspeed_genl_require_string(info, LANSPEED_NSS_A_IFB_NAME,
					     &ifb);
	if (error)
		return error;
	error = lanspeed_genl_require_string(info, LANSPEED_NSS_A_EDGE_NAME,
					     &edge);
	if (error)
		return error;
	if (scnprintf(value, sizeof(value), "%s %s", ifb, edge) >= sizeof(value))
		return -EINVAL;
	return lanspeed_igs_publish(value);
}

static int lanspeed_genl_igs_unpublish(struct sk_buff *skb,
					   struct genl_info *info)
{
	const char *ifb;
	int error = lanspeed_genl_require_string(info, LANSPEED_NSS_A_IFB_NAME,
						 &ifb);

	return error ? error : lanspeed_igs_unpublish(ifb);
}

static int lanspeed_genl_igs_delete(struct sk_buff *skb,
					struct genl_info *info)
{
	const char *ifb;
	int error = lanspeed_genl_require_string(info, LANSPEED_NSS_A_IFB_NAME,
						 &ifb);

	return error ? error : lanspeed_igs_delete(ifb);
}

static int lanspeed_genl_peer_replace(struct sk_buff *skb,
					      struct genl_info *info)
{
	const char *config;
	int error = lanspeed_genl_require_string(info, LANSPEED_NSS_A_CONFIG,
						 &config);

	return error ? error : lanspeed_peer_replace(config);
}

static int lanspeed_genl_tag_replace(struct sk_buff *skb,
					     struct genl_info *info)
{
	const char *config;
	int error = lanspeed_genl_require_string(info, LANSPEED_NSS_A_CONFIG,
						 &config);

	return error ? error : lanspeed_tag_replace(config);
}

static int lanspeed_genl_trusted_ingress_replace(struct sk_buff *skb,
						  struct genl_info *info)
{
	const char *config;
	int error = lanspeed_genl_require_string(info, LANSPEED_NSS_A_CONFIG,
						 &config);

	return error ? error : lanspeed_trusted_ingress_replace(config);
}

static const struct genl_ops lanspeed_genl_ops[] = {
	{
		.cmd = LANSPEED_NSS_CMD_GET_CAPS,
		.doit = lanspeed_genl_get_caps,
	},
	{
		.cmd = LANSPEED_NSS_CMD_GET_STATE,
		.doit = lanspeed_genl_get_state,
	},
	{
		.cmd = LANSPEED_NSS_CMD_GET_STATS,
		.doit = lanspeed_genl_get_stats,
	},
	{
		.cmd = LANSPEED_NSS_CMD_GET_HEALTH,
		.doit = lanspeed_genl_get_health,
	},
	{
		.cmd = LANSPEED_NSS_CMD_IGS_STAGE,
		.doit = lanspeed_genl_igs_stage,
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = LANSPEED_NSS_CMD_IGS_PUBLISH,
		.doit = lanspeed_genl_igs_publish,
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = LANSPEED_NSS_CMD_IGS_UNPUBLISH,
		.doit = lanspeed_genl_igs_unpublish,
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = LANSPEED_NSS_CMD_IGS_DELETE,
		.doit = lanspeed_genl_igs_delete,
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = LANSPEED_NSS_CMD_PEER_REPLACE,
		.doit = lanspeed_genl_peer_replace,
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = LANSPEED_NSS_CMD_TAG_REPLACE,
		.doit = lanspeed_genl_tag_replace,
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = LANSPEED_NSS_CMD_TRUSTED_INGRESS_REPLACE,
		.doit = lanspeed_genl_trusted_ingress_replace,
		.flags = GENL_ADMIN_PERM,
	},
};

static struct genl_family lanspeed_genl_family = {
	.name = LANSPEED_NSS_GENL_NAME,
	.version = LANSPEED_NSS_GENL_VERSION,
	.maxattr = LANSPEED_NSS_A_MAX,
	.policy = lanspeed_genl_policy,
	.ops = lanspeed_genl_ops,
	.n_ops = ARRAY_SIZE(lanspeed_genl_ops),
	.module = THIS_MODULE,
	.netnsok = true,
};

int lanspeed_genl_register(void)
{
	return genl_register_family(&lanspeed_genl_family);
}

void lanspeed_genl_unregister(void)
{
	genl_unregister_family(&lanspeed_genl_family);
}
