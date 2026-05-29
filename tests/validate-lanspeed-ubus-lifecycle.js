#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

const root = path.resolve(__dirname, '..');
const source = fs.readFileSync(path.join(root, 'net/lanspeedd/src/lanspeedd.c'), 'utf8');

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

assert(
  source.includes('static struct uloop_timeout ubus_reconnect_timer;'),
  'lanspeedd must keep a uloop timer for ubus reconnect retries'
);
assert(
  source.includes('static void schedule_ubus_reconnect(void)'),
  'lanspeedd must centralize ubus reconnect scheduling'
);
assert(
  source.includes('ctx->connection_lost = handle_ubus_connection_lost;'),
  'lanspeedd must install a ubus connection_lost handler'
);
assert(
  /handle_ubus_connection_lost[\s\S]{0,500}uloop_fd_delete\(&lost_ctx->sock\)/.test(source),
  'ubus connection_lost handler must remove the dead ubus fd from uloop'
);
assert(
  /ubus_reconnect_cb[\s\S]{0,700}ubus_reconnect\(ctx, NULL\)/.test(source),
  'ubus reconnect callback must call ubus_reconnect'
);
assert(
  /ubus_reconnect_cb[\s\S]{0,1200}ubus_add_object\(ctx, &lanspeed_object\)/.test(source),
  'ubus reconnect callback must re-register the lanspeed object'
);
assert(
  /ubus_reconnect_cb[\s\S]{0,1200}schedule_ubus_reconnect\(\)/.test(source),
  'ubus reconnect callback must retry when reconnect or object registration fails'
);

assert(
  source.includes('static int reload_method('),
  'lanspeedd must expose its own ubus reload method instead of relying on rc init'
);
assert(
  /reload_method[\s\S]{0,1200}reload_runtime_config\(\)/.test(source),
  'lanspeed.reload must reload daemon runtime configuration in-process'
);
assert(
  /lanspeed_methods[\s\S]{0,500}UBUS_METHOD_NOARG\("reload", reload_method\)/.test(source),
  'lanspeed ubus object must register the reload method'
);

console.log('validate-lanspeed-ubus-lifecycle: PASS');
