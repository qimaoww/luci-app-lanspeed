'use strict';
'require baseclass';
'require lanspeed.diagnosticsSchema as schema';
'require lanspeed.diagnosticsResources as resources';
'require lanspeed.diagnosticsStates as states';
'require lanspeed.diagnosticsReportModel as reportModel';

function moduleSurface(module) {
	var surface = {}, prototype = module && Object.getPrototypeOf(module);
	if (!module) return surface;
	Object.keys(module).forEach(function(key) { surface[key] = module[key]; });
	if (prototype) Object.getOwnPropertyNames(prototype).forEach(function(key) {
		if (key !== 'constructor') surface[key] = module[key];
	});
	return surface;
}

var mergedSurface = {};
[ schema, resources, states, reportModel ].forEach(function(module) {
	Object.assign(mergedSurface, moduleSurface(module));
});

/*
 * Compatibility facade for existing views.  Validation, RPC resource
 * lifecycle, derived health state, and report rendering live in their own
 * modules; this file only publishes the stable model surface.
 */
return baseclass.extend(Object.assign(mergedSurface, {
	mergeRuntime: function(status, health, rpc, diagnostics) {
		var source = status || {}, fallback = health || {}, contract = this.diagnosticsContractState({
			status: status, health: health, rpc: rpc, diagnostics: diagnostics
		});
		return Object.assign({}, fallback, source, contract.usable ? {
			version: contract.data.versions.daemon,
			mode: contract.data.collection.state === 'fresh' ? 'Full' : 'Degraded',
			confidence: contract.data.collection.state === 'fresh' ? 'high' : 'low',
			collector: contract.data.data_path.effective_rate,
			capabilities: source.capabilities || fallback.capabilities || {}
		} : {});
	}
}));
