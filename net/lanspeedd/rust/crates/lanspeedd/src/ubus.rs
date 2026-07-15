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
    ClientConnections,
}

impl Method {
    pub const FIXED: [Self; 7] = [
        Self::Status,
        Self::Clients,
        Self::Overview,
        Self::Health,
        Self::Reload,
        Self::Interfaces,
        Self::Sysdevices,
    ];
    pub const ALL: [Self; 8] = [
        Self::Status,
        Self::Clients,
        Self::Overview,
        Self::Health,
        Self::Reload,
        Self::Interfaces,
        Self::Sysdevices,
        Self::ClientConnections,
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
            Self::ClientConnections => "client_connections",
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
) -> Result<lanspeed_openwrt_sys::UbusObject, DaemonError> {
    use lanspeed_openwrt_sys::{
        UbusMethod, UbusObject, STATUS_INVALID_ARGUMENT, STATUS_OK, STATUS_UNKNOWN_ERROR,
    };
    use std::{cell::RefCell, rc::Rc};
    let before_reply = Rc::new(RefCell::new(before_reply));
    let methods = Method::ALL
        .into_iter()
        .map(|method| {
            let snapshots = snapshots.clone();
            let before_reply = Rc::clone(&before_reply);
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
            if method == Method::ClientConnections {
                ubus_method
                    .with_string_policy("identity_key")
                    .map_err(|error| DaemonError::transport(error.to_string()))
            } else {
                Ok(ubus_method)
            }
        })
        .collect::<Result<Vec<_>, _>>()?;
    UbusObject::new("lanspeed", methods).map_err(|error| DaemonError::transport(error.to_string()))
}
