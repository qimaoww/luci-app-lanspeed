#[cfg(feature = "openwrt")]
use crate::control::{
    parse_rate, parse_switch, ClientControlDeleteRequest, ClientControlRequest, ControlCommand,
};
use crate::{error::DaemonError, state::ResponseSnapshot};
use serde_json::Value;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Method {
    Status,
    Clients,
    Overview,
    Health,
    Reload,
    Interfaces,
    Sysdevices,
    Diagnostics,
    ClientConnections,
    ClientControlSet,
    ClientControlDelete,
}

impl Method {
    pub const FIXED: [Self; 8] = [
        Self::Status,
        Self::Clients,
        Self::Overview,
        Self::Health,
        Self::Reload,
        Self::Interfaces,
        Self::Sysdevices,
        Self::Diagnostics,
    ];
    pub const ALL: [Self; 11] = [
        Self::Status,
        Self::Clients,
        Self::Overview,
        Self::Health,
        Self::Reload,
        Self::Interfaces,
        Self::Sysdevices,
        Self::Diagnostics,
        Self::ClientConnections,
        Self::ClientControlSet,
        Self::ClientControlDelete,
    ];
    pub const fn name(self) -> &'static str {
        match self {
            Self::Status => "status",
            Self::Clients => "clients",
            Self::Overview => "overview",
            Self::Health => "health",
            Self::Reload => "reload",
            Self::Interfaces => "interfaces",
            Self::Sysdevices => "sysdevices",
            Self::Diagnostics => "diagnostics",
            Self::ClientConnections => "client_connections",
            Self::ClientControlSet => "client_control_set",
            Self::ClientControlDelete => "client_control_delete",
        }
    }
    pub fn dispatch(self, snapshot: &ResponseSnapshot) -> Result<Value, DaemonError> {
        snapshot.response(self)
    }
}

pub fn validated_identity_key(value: Option<String>) -> Option<String> {
    value.filter(|identity_key| !identity_key.is_empty() && identity_key.len() <= 255)
}

pub fn client_connections_response(
    snapshots: &crate::state::SnapshotStore,
    identity_key: &str,
    mut before_reply: impl FnMut(Method) -> Result<(), DaemonError>,
) -> Result<Value, DaemonError> {
    before_reply(Method::ClientConnections)?;
    snapshots
        .load()
        .response_for_request(Method::ClientConnections, identity_key)
}

#[cfg(feature = "openwrt")]
pub fn object(
    snapshots: crate::state::SnapshotStore,
    before_reply: impl FnMut(Method) -> Result<(), DaemonError> + 'static,
    handle_control: impl FnMut(ControlCommand) -> Result<Value, DaemonError> + 'static,
) -> Result<lanspeed_openwrt_sys::UbusObject, DaemonError> {
    use lanspeed_openwrt_sys::{
        UbusMethod, UbusObject, STATUS_INVALID_ARGUMENT, STATUS_OK, STATUS_UNKNOWN_ERROR,
    };
    use std::{cell::RefCell, rc::Rc};
    let before_reply = Rc::new(RefCell::new(before_reply));
    let handle_control = Rc::new(RefCell::new(handle_control));
    let methods = Method::ALL
        .into_iter()
        .map(|method| {
            let snapshots = snapshots.clone();
            let before_reply = Rc::clone(&before_reply);
            let handle_control = Rc::clone(&handle_control);
            let ubus_method = UbusMethod::new(method.name(), move |mut request| {
                let response = match method {
                    Method::ClientConnections => {
                        let identity_key = match request.string("identity_key") {
                            Ok(value) => validated_identity_key(value),
                            Err(_) => None,
                        };
                        let Some(identity_key) = identity_key else {
                            return STATUS_INVALID_ARGUMENT;
                        };
                        client_connections_response(&snapshots, &identity_key, |method| {
                            before_reply.borrow_mut()(method)
                        })
                    }
                    Method::ClientControlSet => {
                        let identity_key = request
                            .string("identity_key")
                            .ok()
                            .and_then(validated_identity_key);
                        let parsed = identity_key
                            .ok_or_else(|| DaemonError::reload("invalid_identity_key"))
                            .and_then(|identity_key| {
                                Ok(ControlCommand::Set(ClientControlRequest {
                                    identity_key,
                                    upload_bps: parse_rate(
                                        request.string("upload_bps").ok().flatten(),
                                    )?,
                                    download_bps: parse_rate(
                                        request.string("download_bps").ok().flatten(),
                                    )?,
                                    internet_disabled: parse_switch(
                                        request.string("internet_disabled").ok().flatten(),
                                    )?,
                                }))
                            });
                        match parsed.and_then(|command| handle_control.borrow_mut()(command)) {
                            Ok(value) => Ok(value),
                            Err(error) => Ok(control_error(&error)),
                        }
                    }
                    Method::ClientControlDelete => {
                        let parsed = request
                            .string("identity_key")
                            .ok()
                            .and_then(validated_identity_key)
                            .map(|identity_key| {
                                ControlCommand::Delete(ClientControlDeleteRequest { identity_key })
                            })
                            .ok_or_else(|| DaemonError::reload("invalid_identity_key"));
                        match parsed.and_then(|command| handle_control.borrow_mut()(command)) {
                            Ok(value) => Ok(value),
                            Err(error) => Ok(control_error(&error)),
                        }
                    }
                    _ => before_reply.borrow_mut()(method)
                        .and_then(|()| snapshots.load().response(method)),
                }
                .and_then(|value| serde_json::to_string(&value).map_err(DaemonError::from))
                .and_then(|json| {
                    request
                        .reply_json(&json)
                        .map_err(|error| DaemonError::transport(error.to_string()))
                });
                if response.is_ok() {
                    STATUS_OK
                } else {
                    STATUS_UNKNOWN_ERROR
                }
            })
            .map_err(|error| DaemonError::transport(error.to_string()))?;
            match method {
                Method::ClientConnections | Method::ClientControlDelete => ubus_method
                    .with_string_policy("identity_key")
                    .map_err(|error| DaemonError::transport(error.to_string())),
                Method::ClientControlSet => {
                    let method = ubus_method
                        .with_string_policy("identity_key")
                        .map_err(|error| DaemonError::transport(error.to_string()))?;
                    let method = method
                        .with_string_policy("upload_bps")
                        .map_err(|error| DaemonError::transport(error.to_string()))?;
                    let method = method
                        .with_string_policy("download_bps")
                        .map_err(|error| DaemonError::transport(error.to_string()))?;
                    method
                        .with_string_policy("internet_disabled")
                        .map_err(|error| DaemonError::transport(error.to_string()))
                }
                _ => Ok(ubus_method),
            }
        })
        .collect::<Result<Vec<_>, _>>()?;
    UbusObject::new("lanspeed", methods).map_err(|error| DaemonError::transport(error.to_string()))
}

#[cfg(feature = "openwrt")]
fn control_error(error: &DaemonError) -> Value {
    let text = error.to_string();
    let known = [
        "invalid_identity_key",
        "unknown_identity",
        "ambiguous_identity",
        "identity_address_unavailable",
        "invalid_rate",
        "invalid_rate_resolution",
        "missing_rate",
        "rate_below_minimum",
        "rate_above_platform_maximum",
        "invalid_switch",
        "control_rule_limit",
    ];
    let code = known
        .into_iter()
        .find(|code| text.contains(code))
        .unwrap_or("control_apply_failed");
    serde_json::json!({ "ok": false, "error": code })
}

#[cfg(test)]
mod tests {
    use super::Method;

    #[test]
    fn every_platform_registers_both_client_control_methods() {
        assert!(Method::ALL.contains(&Method::ClientControlSet));
        assert!(Method::ALL.contains(&Method::ClientControlDelete));
        assert_eq!(Method::ALL.len(), 11);
    }
}
