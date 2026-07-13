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
}

impl Method {
    pub const ALL: [Self; 7] = [
        Self::Status,
        Self::Clients,
        Self::Overview,
        Self::Health,
        Self::Reload,
        Self::Interfaces,
        Self::Sysdevices,
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
        }
    }
    pub fn dispatch(self, snapshot: &ResponseSnapshot) -> Result<Value, DaemonError> {
        snapshot.response(self)
    }
}

#[cfg(feature = "openwrt")]
pub fn object(
    snapshots: crate::state::SnapshotStore,
    before_reply: impl FnMut(Method) -> Result<(), DaemonError> + 'static,
) -> Result<lanspeed_openwrt_sys::UbusObject, DaemonError> {
    use lanspeed_openwrt_sys::{UbusMethod, UbusObject, STATUS_OK, STATUS_UNKNOWN_ERROR};
    use std::{cell::RefCell, rc::Rc};
    let before_reply = Rc::new(RefCell::new(before_reply));
    let methods = Method::ALL
        .into_iter()
        .map(|method| {
            let snapshots = snapshots.clone();
            let before_reply = Rc::clone(&before_reply);
            UbusMethod::new(method.name(), move |mut request| {
                if before_reply.borrow_mut()(method).is_err() {
                    return STATUS_UNKNOWN_ERROR;
                }
                let response = snapshots
                    .load()
                    .response(method)
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
            .map_err(|error| DaemonError::transport(error.to_string()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    UbusObject::new("lanspeed", methods).map_err(|error| DaemonError::transport(error.to_string()))
}
