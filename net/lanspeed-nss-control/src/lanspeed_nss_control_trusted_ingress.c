// SPDX-License-Identifier: GPL-2.0-only

#include <linux/mutex.h>
#include <linux/netdevice.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/string.h>

#include "lanspeed_nss_control.h"

#define LANSPEED_MAX_EDGE_DEVICES 64
#define LANSPEED_TRUSTED_INGRESS_INPUT 4095

struct lanspeed_published_edge_set {
	struct rcu_head rcu;
	u16 count;
	struct net_device *edges[LANSPEED_MAX_EDGE_DEVICES];
};

struct lanspeed_trusted_ingress {
	struct rcu_head rcu;
	u16 count;
	struct net_device *edges[LANSPEED_MAX_EDGE_DEVICES];
};

static struct lanspeed_published_edge_set lanspeed_empty_published_edges;
static struct lanspeed_published_edge_set __rcu *lanspeed_published_edges =
	&lanspeed_empty_published_edges;
static struct lanspeed_trusted_ingress lanspeed_empty_trusted_ingress;
static struct lanspeed_trusted_ingress __rcu *lanspeed_trusted_ingress =
	&lanspeed_empty_trusted_ingress;

static void lanspeed_published_edges_free(struct rcu_head *rcu)
{
	struct lanspeed_published_edge_set *set;
	u16 index;

	set = container_of(rcu, struct lanspeed_published_edge_set, rcu);
	for (index = 0; index < set->count; index++)
		dev_put(set->edges[index]);
	kfree(set);
}

static void lanspeed_trusted_ingress_free(struct rcu_head *rcu)
{
	struct lanspeed_trusted_ingress *set;
	u16 index;

	set = container_of(rcu, struct lanspeed_trusted_ingress, rcu);
	for (index = 0; index < set->count; index++)
		dev_put(set->edges[index]);
	kfree(set);
}

bool lanspeed_edge_add(struct net_device *edge)
{
	struct lanspeed_published_edge_set *old;
	struct lanspeed_published_edge_set *set;
	u16 index;

	old = rcu_dereference_protected(lanspeed_published_edges,
					lockdep_is_held(&lanspeed_igs_lock));
	for (index = 0; index < old->count; index++) {
		if (old->edges[index] == edge)
			return true;
	}
	if (old->count >= LANSPEED_MAX_EDGE_DEVICES)
		return false;
	set = kzalloc(sizeof(*set), GFP_KERNEL);
	if (!set)
		return false;
	for (index = 0; index < old->count; index++) {
		set->edges[index] = old->edges[index];
		dev_hold(set->edges[index]);
	}
	set->edges[old->count] = edge;
	dev_hold(edge);
	set->count = old->count + 1;
	rcu_assign_pointer(lanspeed_published_edges, set);
	if (old != &lanspeed_empty_published_edges)
		call_rcu(&old->rcu, lanspeed_published_edges_free);
	return true;
}

bool lanspeed_edge_del(struct net_device *edge)
{
	struct lanspeed_published_edge_set *old;
	struct lanspeed_published_edge_set *set;
	u16 index;
	u16 output = 0;

	old = rcu_dereference_protected(lanspeed_published_edges,
					lockdep_is_held(&lanspeed_igs_lock));
	for (index = 0; index < old->count; index++) {
		if (old->edges[index] == edge)
			continue;
		output++;
	}
	if (output == old->count)
		return true;
	set = kzalloc(sizeof(*set), GFP_KERNEL);
	if (!set)
		return false;
	output = 0;
	for (index = 0; index < old->count; index++) {
		if (old->edges[index] == edge)
			continue;
		set->edges[output++] = old->edges[index];
		dev_hold(set->edges[output - 1]);
	}
	set->count = output;
	rcu_assign_pointer(lanspeed_published_edges, set);
	if (old != &lanspeed_empty_published_edges)
		call_rcu(&old->rcu, lanspeed_published_edges_free);
	return true;
}

bool lanspeed_edge_published(struct net_device *edge)
{
	const struct lanspeed_published_edge_set *set;
	u16 index;

	if (!edge)
		return false;
	rcu_read_lock();
	set = rcu_dereference(lanspeed_published_edges);
	for (index = 0; index < set->count; index++) {
		if (set->edges[index] == edge) {
			rcu_read_unlock();
			return true;
		}
	}
	rcu_read_unlock();
	return false;
}

bool lanspeed_trusted_ingress_contains(struct net_device *edge)
{
	const struct lanspeed_published_edge_set *published;
	const struct lanspeed_trusted_ingress *trusted;
	u16 index;

	if (!edge)
		return false;
	rcu_read_lock();
	trusted = rcu_dereference(lanspeed_trusted_ingress);
	for (index = 0; index < trusted->count; index++) {
		if (trusted->edges[index] == edge) {
			rcu_read_unlock();
			return true;
		}
	}
	published = rcu_dereference(lanspeed_published_edges);
	for (index = 0; index < published->count; index++) {
		if (published->edges[index] == edge) {
			rcu_read_unlock();
			return true;
		}
	}
	rcu_read_unlock();
	return false;
}

int lanspeed_trusted_ingress_replace(const char *value)
{
	struct lanspeed_trusted_ingress *old;
	struct lanspeed_trusted_ingress *set;
	struct net_device *dev;
	char *input;
	char *cursor;
	char *field;
	u16 index;
	int error = -EINVAL;

	if (!value)
		return -EINVAL;
	if (strnlen(value, LANSPEED_TRUSTED_INGRESS_INPUT + 1) >
	    LANSPEED_TRUSTED_INGRESS_INPUT)
		return -E2BIG;
	input = kstrndup(value, LANSPEED_TRUSTED_INGRESS_INPUT, GFP_KERNEL);
	if (!input)
		return -ENOMEM;
	cursor = strim(input);
	field = strsep(&cursor, " \t");
	if (!field || strcmp(field, "v1"))
		goto out_input;
	set = kzalloc(sizeof(*set), GFP_KERNEL);
	if (!set) {
		error = -ENOMEM;
		goto out_input;
	}
	while (cursor) {
		field = strsep(&cursor, " \t");
		if (!field || !*field)
			continue;
		if (set->count >= LANSPEED_MAX_EDGE_DEVICES)
			goto out_set;
		dev = dev_get_by_name(&init_net, field);
		if (!dev)
			goto out_set;
		for (index = 0; index < set->count; index++) {
			if (set->edges[index] == dev) {
				dev_put(dev);
				goto out_set;
			}
		}
		set->edges[set->count++] = dev;
	}

	mutex_lock(&lanspeed_igs_lock);
	old = rcu_dereference_protected(lanspeed_trusted_ingress,
					lockdep_is_held(&lanspeed_igs_lock));
	rcu_assign_pointer(lanspeed_trusted_ingress, set);
	mutex_unlock(&lanspeed_igs_lock);
	if (old != &lanspeed_empty_trusted_ingress)
		call_rcu(&old->rcu, lanspeed_trusted_ingress_free);
	set = NULL;
	error = 0;
out_set:
	if (set) {
		for (index = 0; index < set->count; index++)
			dev_put(set->edges[index]);
		kfree(set);
	}
out_input:
	kfree(input);
	return error;
}

void lanspeed_trusted_ingress_cleanup(void)
{
	struct lanspeed_trusted_ingress *old;

	mutex_lock(&lanspeed_igs_lock);
	old = rcu_dereference_protected(lanspeed_trusted_ingress,
					lockdep_is_held(&lanspeed_igs_lock));
	RCU_INIT_POINTER(lanspeed_trusted_ingress, &lanspeed_empty_trusted_ingress);
	mutex_unlock(&lanspeed_igs_lock);
	if (old != &lanspeed_empty_trusted_ingress)
		call_rcu(&old->rcu, lanspeed_trusted_ingress_free);
}

void lanspeed_published_edges_cleanup(void)
{
	struct lanspeed_published_edge_set *old;

	mutex_lock(&lanspeed_igs_lock);
	old = rcu_dereference_protected(lanspeed_published_edges,
					lockdep_is_held(&lanspeed_igs_lock));
	RCU_INIT_POINTER(lanspeed_published_edges, &lanspeed_empty_published_edges);
	mutex_unlock(&lanspeed_igs_lock);
	if (old != &lanspeed_empty_published_edges)
		call_rcu(&old->rcu, lanspeed_published_edges_free);
}
