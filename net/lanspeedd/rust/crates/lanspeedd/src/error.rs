use std::{error::Error, fmt};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DaemonError {
    Transport(String),
    Collection(String),
    Reload(String),
    Serialization(String),
    Platform(String),
}

impl DaemonError {
    pub fn transport(message: impl Into<String>) -> Self {
        Self::Transport(message.into())
    }
    pub fn collection(message: impl Into<String>) -> Self {
        Self::Collection(message.into())
    }
    pub fn reload(message: impl Into<String>) -> Self {
        Self::Reload(message.into())
    }
    pub fn platform(message: impl Into<String>) -> Self {
        Self::Platform(message.into())
    }
}

impl fmt::Display for DaemonError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (kind, message) = match self {
            Self::Transport(message) => ("transport", message),
            Self::Collection(message) => ("collection", message),
            Self::Reload(message) => ("reload", message),
            Self::Serialization(message) => ("serialization", message),
            Self::Platform(message) => ("platform", message),
        };
        write!(formatter, "{kind}: {message}")
    }
}

impl Error for DaemonError {}

impl From<serde_json::Error> for DaemonError {
    fn from(error: serde_json::Error) -> Self {
        Self::Serialization(error.to_string())
    }
}
