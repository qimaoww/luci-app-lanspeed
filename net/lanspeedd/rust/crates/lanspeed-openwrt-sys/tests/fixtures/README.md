# OpenWrt wire golden fixtures

These byte-for-byte fixtures were generated independently with the real
ImmortalWrt 25.12 SDK libraries, not with the Rust codec under test.

- `blobmsg-json.hex` is the root blob produced by `blobmsg_add_json_from_string()`
  from `libubox`/`libblobmsg-json` for the JSON object used by the codec test.
- `ubus-add-object.hex` is the complete `UBUS_MSG_ADD_OBJECT` frame emitted by
  `libubus` after a synthetic ubusd `HELLO`. It registers `lanspeed.test` with
  `status` and `client_connections`; the latter has a string `identity_key`
  policy.

The fixtures intentionally stay as readable hexadecimal so they are portable
across host architectures and do not require native OpenWrt libraries at test
runtime.
