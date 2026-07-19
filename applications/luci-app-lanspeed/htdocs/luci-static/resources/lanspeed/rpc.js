'use strict';
'require baseclass';
'require rpc';

/*
 * LAN Speed RPC module.
 *
 * Declares every ubus / uci call the LuCI views need and exposes them as
 * pre-bound call* functions. Consumers should never re-declare RPC handles.
 */

var callStatus = rpc.declare({
	object: 'lanspeed',
	method: 'status',
	expect: { '': {} }
});
var callClients = rpc.declare({
	object: 'lanspeed',
	method: 'clients',
	expect: { '': {} }
});
var callClientConnections = rpc.declare({
	object: 'lanspeed',
	method: 'client_connections',
	params: [ 'identity_key' ],
	expect: { '': {} }
});
var callOverview = rpc.declare({
	object: 'lanspeed',
	method: 'overview',
	expect: { '': {} }
});
var callHealth = rpc.declare({
	object: 'lanspeed',
	method: 'health',
	expect: { '': {} }
});
var callInterfaces = rpc.declare({
	object: 'lanspeed',
	method: 'interfaces',
	expect: { '': {} }
});
var callSysdevices = rpc.declare({
	object: 'lanspeed',
	method: 'sysdevices',
	expect: { '': {} }
});
var callDiagnostics = rpc.declare({
	object: 'lanspeed',
	method: 'diagnostics',
	expect: { '': {} }
});
var callUciSet = rpc.declare({
	object: 'uci',
	method: 'set',
	params: [ 'config', 'section', 'values' ]
});
var callUciAdd = rpc.declare({
	object: 'uci',
	method: 'add',
	params: [ 'config', 'type', 'name' ],
	expect: { section: '' }
});
var callUciGet = rpc.declare({
	object: 'uci',
	method: 'get',
	params: [ 'config', 'section' ],
	expect: { values: {} }
});
var callUciDelete = rpc.declare({
	object: 'uci',
	method: 'delete',
	params: [ 'config', 'section', 'options' ]
});
var callUciRevert = rpc.declare({
	object: 'uci',
	method: 'revert',
	params: [ 'config' ]
});

return baseclass.extend({
	status:     callStatus,
	clients:    callClients,
	clientConnections: callClientConnections,
	overview:   callOverview,
	health:     callHealth,
	interfaces: callInterfaces,
	sysdevices: callSysdevices,
	diagnostics: callDiagnostics,
	uciSet:     callUciSet,
	uciAdd:     callUciAdd,
	uciGet:     callUciGet,
	uciDelete:  callUciDelete,
	uciRevert:  callUciRevert
});
