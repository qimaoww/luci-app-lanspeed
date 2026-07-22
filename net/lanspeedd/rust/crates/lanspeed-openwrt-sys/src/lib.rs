#![deny(unsafe_op_in_unsafe_fn)]

mod codec;
mod error;
mod pure_blob;
mod pure_ubus;
mod pure_uci;
mod pure_uloop;

pub use error::{Error, Result};
pub use pure_blob::BlobBuf;
pub use pure_ubus::{
    UbusConnection, UbusMethod, UbusObject, UbusRequest, STATUS_INVALID_ARGUMENT, STATUS_OK,
    STATUS_UNKNOWN_ERROR,
};
pub use pure_uci::{UciContext, UciOption, UciPackage, UciSection, UciValue};
pub use pure_uloop::{Signal, Timer, UloopGuard};
