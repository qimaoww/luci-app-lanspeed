'use strict';
'require baseclass';

function routedSource(meta, direction) {
	if (!meta || typeof meta !== 'object' || meta.scope !== 'routed_observed')
		return '';
	var value = meta[direction];
	var source = value && String(value.source || '');
	return source === 'fast_routed_internet' || source === 'fast_routed_lease'
		? source : '';
}

function routedCollector(meta) {
	if (!meta || typeof meta !== 'object' || meta.scope !== 'routed_observed')
		return '';
	var tx = routedSource(meta, 'tx');
	var rx = routedSource(meta, 'rx');
	if (!tx || !rx) return '';
	return tx === 'fast_routed_lease' || rx === 'fast_routed_lease'
		? 'fast_routed_lease' : 'fast_routed_internet';
}

return baseclass.extend({
	routedSource: routedSource,
	routedCollector: routedCollector
});
