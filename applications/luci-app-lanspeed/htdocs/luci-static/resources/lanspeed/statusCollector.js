'use strict';
'require baseclass';

function collectorLabel(mode) {
	mode = String(mode || '-');
	if (mode === 'access_edge')
		return _('自动精准');
	if (mode === 'bpf')
		return _('BPF');
	if (mode === 'nss_ecm_node')
		return 'ECM';
	if (mode === 'nss_ecm_bpf')
		return _('ECM+BPF');
	if (mode === 'fast_routed_internet')
		return 'FastN+FastS routed Internet';
	if (mode === 'fast_routed_lease')
		return 'FastN+FastS lease';
	if (mode === 'conntrack_netlink')
		return 'CT-Netlink';
	if (mode === 'conntrack_procfs')
		return 'CT-Procfs';
	if (mode === 'conntrack')
		return 'CT';
	if (mode === 'unsupported')
		return _('不可用');
	return mode === '-' ? '-' : mode;
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
