use std::{
    io::{self, Read, Write},
    net::{Ipv4Addr, SocketAddrV4, TcpStream},
    time::Duration,
};

const LOOPBACK_TIMEOUT: Duration = Duration::from_millis(750);
const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
const MAX_HEADER_BYTES: usize = 32 * 1024;

pub(super) fn get_loopback_json(
    port: u16,
    path: &str,
    bearer: Option<&str>,
) -> io::Result<Vec<u8>> {
    if !path.starts_with('/') || path.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid HTTP path",
        ));
    }
    if bearer.is_some_and(|value| {
        value.is_empty() || !value.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
    }) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid HTTP bearer token",
        ));
    }
    let address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, port);
    let mut stream = TcpStream::connect_timeout(&address.into(), LOOPBACK_TIMEOUT)?;
    stream.set_read_timeout(Some(LOOPBACK_TIMEOUT))?;
    stream.set_write_timeout(Some(LOOPBACK_TIMEOUT))?;

    let mut request = format!(
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nAccept: application/json\r\nConnection: close\r\n"
    );
    if let Some(bearer) = bearer {
        request.push_str("Authorization: Bearer ");
        request.push_str(bearer);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes())?;

    let mut response = Vec::new();
    stream
        .take((MAX_RESPONSE_BYTES + 1) as u64)
        .read_to_end(&mut response)?;
    if response.len() > MAX_RESPONSE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "HTTP response exceeds limit",
        ));
    }
    parse_response(&response)
}

fn parse_response(response: &[u8]) -> io::Result<Vec<u8>> {
    let header_end = find_bytes(response, b"\r\n\r\n")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "HTTP headers incomplete"))?;
    if header_end > MAX_HEADER_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "HTTP headers exceed limit",
        ));
    }
    let header = std::str::from_utf8(&response[..header_end])
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "HTTP headers are not UTF-8"))?;
    let mut lines = header.split("\r\n");
    let status = lines
        .next()
        .and_then(|line| line.split_ascii_whitespace().nth(1))
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid HTTP status"))?;
    if status != 200 {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("loopback API returned HTTP {status}"),
        ));
    }

    let mut content_length = None;
    let mut chunked = false;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "malformed HTTP header",
            ));
        };
        let value = value.trim();
        if name.eq_ignore_ascii_case("content-length") {
            let length = value.parse::<usize>().map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid HTTP content length")
            })?;
            if content_length.replace(length).is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "duplicate HTTP content length",
                ));
            }
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            chunked = value
                .split(',')
                .any(|encoding| encoding.trim().eq_ignore_ascii_case("chunked"));
        }
    }
    let body = response
        .get(header_end + 4..)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "HTTP body missing"))?;
    if chunked {
        return decode_chunked(body);
    }
    if let Some(length) = content_length {
        if length > MAX_RESPONSE_BYTES || body.len() != length {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP body length mismatch",
            ));
        }
    }
    Ok(body.to_vec())
}

fn decode_chunked(mut bytes: &[u8]) -> io::Result<Vec<u8>> {
    let mut decoded = Vec::new();
    loop {
        let line_end = find_bytes(bytes, b"\r\n").ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "chunk size line incomplete")
        })?;
        let size_text = std::str::from_utf8(&bytes[..line_end])
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid chunk size"))?;
        let size = usize::from_str_radix(size_text.split(';').next().unwrap_or(""), 16)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid chunk size"))?;
        bytes = bytes
            .get(line_end + 2..)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "chunk missing"))?;
        if size == 0 {
            if bytes.starts_with(b"\r\n") || find_bytes(bytes, b"\r\n\r\n").is_some() {
                return Ok(decoded);
            }
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "chunk trailer incomplete",
            ));
        }
        if decoded.len().saturating_add(size) > MAX_RESPONSE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "chunked HTTP body exceeds limit",
            ));
        }
        let chunk = bytes
            .get(..size)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "chunk truncated"))?;
        if bytes.get(size..size + 2) != Some(b"\r\n") {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "chunk terminator missing",
            ));
        }
        decoded.extend_from_slice(chunk);
        bytes = &bytes[size + 2..];
    }
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    (!needle.is_empty())
        .then(|| {
            haystack
                .windows(needle.len())
                .position(|window| window == needle)
        })
        .flatten()
}

#[cfg(test)]
mod tests {
    use super::parse_response;

    #[test]
    fn parses_bounded_content_length_and_chunked_json() {
        assert_eq!(
            parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}").unwrap(),
            b"{}"
        );
        assert_eq!(
            parse_response(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n"
            )
            .unwrap(),
            b"{}"
        );
    }

    #[test]
    fn rejects_non_success_and_truncated_responses() {
        assert!(parse_response(b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n").is_err());
        assert!(parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n{}").is_err());
        assert!(
            parse_response(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\n{}")
                .is_err()
        );
    }
}
