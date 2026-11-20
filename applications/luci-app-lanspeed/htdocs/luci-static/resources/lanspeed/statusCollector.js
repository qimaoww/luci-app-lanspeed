'use strict';
'require baseclass';

function collectorLabel(mode) {
	mode = String(mode || '-');
	if (mode === 'access_edge')
		return _('自动精准');
	if (mode === 'bpf')
		return _('包过滤采集');
	if (mode === 'nss_ecm_node')
		return _('加速引擎采集');
	if (mode === 'nss_ecm_bpf')
		return _('加速引擎与包过滤采集');
	if (mode === 'fast_routed_internet')
		return _('互联网流量观察');
	if (mode === 'fast_routed_lease')
		return _('互联网流量租约');
	if (mode === 'conntrack_netlink')
		return _('连接跟踪消息采集');
	if (mode === 'conntrack_procfs')
		return _('连接跟踪文件采集');
	if (mode === 'conntrack')
		return _('连接跟踪');
	if (mode === 'unsupported')
		return _('不可用');
	return _('未知采集方式');
}

function collectorClass(mode) {
	mode = String(mode || '-');
	if (mode === 'access_edge' || mode === 'bpf' || mode === 'nss_ecm_node' || mode === 'nss_ecm_bpf' ||
		mode === 'fast_routed_internet' || mode === 'fast_routed_lease')
		return 'label label-success';
	return 'label label-danger';
}

function effectiveCollector(status, clientsData) {
	var evidence = (status && status.evidence) || {};
	var clientEvidence = (clientsData && clientsData.evidence) || {};
	var collector = clientEvidence.primary_source ||
	                clientEvidence.collector_mode ||
	                evidence.effective_collector ||
	                (evidence.collector && evidence.collector.primary_source);

	return (collector && collector !== 'auto') ? collector : 'unsupported';
}

return baseclass.extend({
	collectorLabel: function(mode) {
		return collectorLabel(mode);
	},

	collectorClass: function(mode) {
		return collectorClass(mode);
	},

	effectiveCollector: function(status, clientsData) {
		return effectiveCollector(status, clientsData);
	}
});
