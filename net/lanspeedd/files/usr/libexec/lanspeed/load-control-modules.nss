#!/bin/sh

# NSS-only boot/reload preparation.  This file is installed only by the
# qualcommax package so other platforms never probe Qualcomm kernel modules.
[ -x /sbin/modprobe ] || exit 0

for module in qca_nss_qdisc act_nssmirred; do
	[ -d "/sys/module/$module" ] || /sbin/modprobe "$module" >/dev/null 2>&1 || true
done

exit 0
