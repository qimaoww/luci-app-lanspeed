use super::{http, normalize_ip, ProxyConnectionSample, ProxyConnectionSettings, ProxySource};
use crate::connection_details::ConnectionProtocol;
use lanspeed_openwrt_sys::{UciContext, UciValue};
use serde::Deserialize;
use std::{io, net::IpAddr};

const DEFAULT_CONTROLLER_PORT: u16 = 9090;
const MAX_PROXY_CONNECTIONS: usize = 16_384;
const MAX_GENERATION_LEN: usize = 128;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
struct ConnectionsResponse {
    #[serde(default)]
    connections: Vec<MihomoConnection>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
struct MihomoConnection {
    id: String,
    metadata: MihomoMetadata,
    upload: u64,
    download: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
struct MihomoMetadata {
    network: String,
    #[serde(rename = "sourceIP")]
    source_ip: String,
    #[serde(rename = "sourcePort")]
    source_port: PortValue,
    #[serde(rename = "destinationIP", default)]
    destination_ip: String,
    #[serde(rename = "destinationPort")]
    destination_port: PortValue,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(untagged)]
enum PortValue {
    String(String),
    Number(u16),
}

impl PortValue {
    fn get(&self) -> Option<u16> {
        match self {
            Self::String(value) => value.parse().ok(),
            Self::Number(value) => Some(*value),
        }
        .filter(|port| *port != 0)
    }
}

pub(super) fn read_samples(
    settings: &ProxyConnectionSettings,
) -> io::Result<Vec<ProxyConnectionSample>> {
    let Some(config) = read_config(settings)? else {
        return Ok(Vec::new());
    };
    let body = http::get_loopback_json(
        config.port,
        "/connections",
        (!config.secret.is_empty()).then_some(config.secret.as_str()),
    )?;
    parse_samples(&body)
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct MihomoControllerConfig {
    port: u16,
    secret: String,
}

fn read_config(settings: &ProxyConnectionSettings) -> io::Result<Option<MihomoControllerConfig>> {
    let mut uci = UciContext::new().map_err(uci_error)?;
    let enabled = uci
        .lookup("openclash.config.enable")
        .map_err(uci_error)?
        .and_then(string_value)
        .is_some_and(|value| value == "1");
    let openclash_port = uci
        .lookup("openclash.config.cn_port")
        .map_err(uci_error)?
        .and_then(string_value)
        .and_then(|value| value.parse::<u16>().ok())
        .filter(|port| *port != 0);
    let openclash_secret = uci
        .lookup("openclash.config.dashboard_password")
        .map_err(uci_error)?
        .and_then(string_value);
    Ok(resolve_config(
        settings,
        enabled,
        openclash_port,
        openclash_secret,
    ))
}

fn resolve_config(
    settings: &ProxyConnectionSettings,
    openclash_enabled: bool,
    openclash_port: Option<u16>,
    openclash_secret: Option<String>,
) -> Option<MihomoControllerConfig> {
    let manually_configured =
        settings.mihomo_controller_port.is_some() || settings.mihomo_controller_secret.is_some();
    if !openclash_enabled && !manually_configured {
        return None;
    }
    Some(MihomoControllerConfig {
        port: settings
            .mihomo_controller_port
            .or(openclash_port)
            .unwrap_or(DEFAULT_CONTROLLER_PORT),
        secret: settings
            .mihomo_controller_secret
            .clone()
            .or(openclash_secret)
            .unwrap_or_default(),
    })
}

fn string_value(value: UciValue) -> Option<String> {
    match value {
        UciValue::String(value) => Some(value),
        UciValue::List(_) => None,
    }
}

fn uci_error(error: lanspeed_openwrt_sys::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}

fn parse_samples(bytes: &[u8]) -> io::Result<Vec<ProxyConnectionSample>> {
    let response = serde_json::from_slice::<ConnectionsResponse>(bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid Mihomo response"))?;
    if response.connections.len() > MAX_PROXY_CONNECTIONS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Mihomo connection count exceeds limit",
        ));
    }
    Ok(response
        .connections
        .into_iter()
        .filter_map(normalize_connection)
        .collect())
}

fn normalize_connection(connection: MihomoConnection) -> Option<ProxyConnectionSample> {
    if connection.id.is_empty() || connection.id.len() > MAX_GENERATION_LEN {
        return None;
    }
    let protocol = match connection.metadata.network.as_str() {
        "tcp" => ConnectionProtocol::Tcp,
        "udp" => ConnectionProtocol::Udp,
        _ => return None,
    };
    let client_ip = normalize_ip(connection.metadata.source_ip.parse::<IpAddr>().ok()?);
    if client_ip.is_unspecified() || client_ip.is_loopback() || client_ip.is_multicast() {
        return None;
    }
    let client_port = connection.metadata.source_port.get()?;
    let remote_port = connection.metadata.destination_port.get()?;
    let remote_ip = (!connection.metadata.destination_ip.is_empty())
        .then(|| connection.metadata.destination_ip.parse::<IpAddr>().ok())
        .flatten()
        .map(normalize_ip)
        .filter(|address| !address.is_unspecified() && !address.is_multicast());
    Some(ProxyConnectionSample {
        source: ProxySource::Mihomo,
        generation: connection.id,
        client_ip,
        client_port,
        remote_ip,
        remote_port,
        protocol,
        tx_bytes: Some(connection.upload),
        rx_bytes: Some(connection.download),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_real_controller_shape_and_retains_unresolved_destination_for_join() {
        let samples = parse_samples(
            br#"{
              "connections": [
                {"id":"tcp-a","metadata":{"network":"tcp","sourceIP":"192.0.2.10",
                 "sourcePort":"50123","destinationIP":"198.51.100.20","destinationPort":"443"},
                 "upload":400,"download":900},
                {"id":"tcp-b","metadata":{"network":"tcp","sourceIP":"192.0.2.10",
                 "sourcePort":"50124","destinationIP":"","destinationPort":"443"},
                 "upload":500,"download":1000},
                {"id":"inner","metadata":{"network":"tcp","sourceIP":"",
                 "sourcePort":"0","destinationIP":"203.0.113.1","destinationPort":"443"},
                 "upload":1,"download":2}
              ]
            }"#,
        )
        .unwrap();
        assert_eq!(samples.len(), 2);
        assert_eq!(samples[0].remote_ip, Some("198.51.100.20".parse().unwrap()));
        assert_eq!(samples[1].remote_ip, None);
        assert_eq!(
            (samples[1].tx_bytes, samples[1].rx_bytes),
            (Some(500), Some(1000))
        );
    }

    #[test]
    fn manual_settings_override_openclash_without_exposing_the_secret() {
        let settings = ProxyConnectionSettings {
            enabled: true,
            mihomo_controller_port: Some(9_091),
            mihomo_controller_secret: Some("manual-token".into()),
        };
        let config = resolve_config(
            &settings,
            false,
            Some(9_090),
            Some("openclash-token".to_owned()),
        )
        .unwrap();
        assert_eq!(config.port, 9_091);
        assert_eq!(config.secret, "manual-token");
    }

    #[test]
    fn automatic_settings_follow_only_an_enabled_openclash_instance() {
        let settings = ProxyConnectionSettings::default();
        assert!(resolve_config(&settings, false, Some(9_090), Some("token".into())).is_none());
        let config = resolve_config(&settings, true, Some(9_090), Some("token".into())).unwrap();
        assert_eq!(config.port, 9_090);
        assert_eq!(config.secret, "token");
    }

    #[test]
    fn rejects_oversized_or_malformed_snapshots_without_leaking_payload() {
        assert!(parse_samples(br#"{"connections":{}}"#).is_err());
        let mut response = String::from("{\"connections\":[");
        for index in 0..=MAX_PROXY_CONNECTIONS {
            if index != 0 {
                response.push(',');
            }
            response.push_str(
                "{\"id\":\"x\",\"metadata\":{\"network\":\"tcp\",\"sourceIP\":\"192.0.2.1\",\"sourcePort\":1,\"destinationIP\":\"198.51.100.1\",\"destinationPort\":1},\"upload\":0,\"download\":0}",
            );
        }
        response.push_str("]}");
        assert!(parse_samples(response.as_bytes()).is_err());
    }
}
