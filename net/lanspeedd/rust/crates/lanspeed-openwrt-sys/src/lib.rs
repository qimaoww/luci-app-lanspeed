#![deny(unsafe_op_in_unsafe_fn)]

mod blob;
mod error;
#[allow(
    dead_code,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unsafe_op_in_unsafe_fn
)]
mod raw;
mod ubus;
mod uci;
mod uloop;

pub use blob::BlobBuf;
pub use error::{Error, Result};
pub use ubus::{
    UbusConnection, UbusMethod, UbusObject, UbusRequest, STATUS_OK, STATUS_UNKNOWN_ERROR,
};
pub use uci::{UciContext, UciOption, UciPackage, UciSection, UciValue};
pub use uloop::{Signal, Timer, UloopGuard};
