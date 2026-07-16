'use strict';
'require baseclass';
'require rpc';

/*
 * LAN Speed RPC module.
 *
 * Declares every ubus / rc / uci call the LuCI view needs and exposes them
 * as pre-bound call* functions.  Consumers call lsRpc.status(), lsRpc.reload(),
 * etc.; they should never re-declare rpc handles themselves.
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
var callReload = rpc.declare({
	object: 'lanspeed',
	method: 'reload',
	expect: { '': {} }
});
var callUciSet = rpc.declare({
	object: 'uci',
	method: 'set',
	params: [ 'config', 'section', 'values' ]
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
var callUciCommit = rpc.declare({
	object: 'uci',
	method: 'commit',
	params: [ 'config' ]
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
	reload:     callReload,
	uciSet:     callUciSet,
	uciGet:     callUciGet,
	uciDelete:  callUciDelete,
	uciCommit:  callUciCommit,
	uciRevert:  callUciRevert
});
