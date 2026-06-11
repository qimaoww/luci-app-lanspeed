'use strict';
'require baseclass';

function collectorLabel(mode) {
	mode = String(mode || '-');
	if (mode === 'bpf')
		return 'BPF';
	if (mode === 'nss_ecm_direct')
		return 'NSS-direct';
	if (mode === 'nss_ecm_direct+conntrack_ecm_sync')
		return 'NSS-direct / NSS sync';
	if (mode === 'conntrack_ecm_sync' || mode === 'nss_conntrack_sync')
		return 'NSS sync';
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
	if (mode === 'bpf' || mode === 'nss_ecm_direct')
		return 'label label-success';
	if (mode === 'nss_ecm_direct+conntrack_ecm_sync')
		return 'label label-warning';
	if (mode === 'conntrack_ecm_sync' || mode === 'nss_conntrack_sync')
		return 'label label-warning';
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
