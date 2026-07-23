use std::{
    io,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
};

const NETLINK_HEADER_LEN: usize = 16;
const TCMSG_IFINDEX_OFFSET: usize = 4;
const TCMSG_MIN_LEN: usize = 8;
const RECEIVE_BUFFER_LEN: usize = 64 * 1024;
const MAX_DRAIN_DATAGRAMS: usize = 64;

/// A best-effort RTNetlink multicast listener for changes to TC qdiscs and
/// filters. Failure is intentionally represented as `None`: callers then run
/// the full `tc` audit every sampling cycle instead of trusting a blind spot.
pub(super) struct TcTopologyMonitor {
    socket: Option<OwnedFd>,
    receive_buffer: Box<[u8]>,
}

impl TcTopologyMonitor {
    pub(super) fn new() -> Self {
        let socket = open_socket().ok();
        Self {
            receive_buffer: if socket.is_some() {
                vec![0u8; RECEIVE_BUFFER_LEN].into_boxed_slice()
            } else {
                Box::default()
            },
            socket,
        }
    }

    /// Drain all currently queued TC notifications.
    ///
    /// `true` means the caller must perform an exact `tc-full` audit. This is
    /// also returned for overflow, malformed messages, socket errors, and an
    /// unavailable listener so the optimization can never weaken correctness.
    pub(super) fn topology_changed(&mut self, expected_ifindices: &[i32]) -> bool {
        if expected_ifindices.is_empty() {
            return true;
        }
        let Some(socket) = self.socket.as_ref() else {
            return true;
        };
        let fd = socket.as_raw_fd();
        let mut changed = false;

        for _ in 0..MAX_DRAIN_DATAGRAMS {
            let mut sender = unsafe { std::mem::zeroed::<libc::sockaddr_nl>() };
            let mut sender_len = std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t;
            let received = unsafe {
                libc::recvfrom(
                    fd,
                    self.receive_buffer.as_mut_ptr().cast(),
                    self.receive_buffer.len(),
                    libc::MSG_DONTWAIT | libc::MSG_TRUNC,
                    (&raw mut sender).cast(),
                    &mut sender_len,
                )
            };
            if received < 0 {
                let error = io::Error::last_os_error();
                match error.raw_os_error() {
                    Some(libc::EINTR) => continue,
                    Some(code) if code == libc::EAGAIN || code == libc::EWOULDBLOCK => {
                        return changed;
                    }
                    _ => {
                        self.socket = None;
                        return true;
                    }
                }
            }
            if received == 0
                || received as usize > self.receive_buffer.len()
                || sender_len < std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t
                || sender.nl_family != libc::AF_NETLINK as libc::sa_family_t
                || sender.nl_pid != 0
            {
                return true;
            }
            match datagram_has_expected_tc_change(
                &self.receive_buffer[..received as usize],
                expected_ifindices,
            ) {
                Ok(observed) => changed |= observed,
                Err(()) => return true,
            }
        }

        // A continuously full queue cannot prove that it was drained to a
        // stable point, so force an audit and try again on the next sample.
        true
    }
}

fn open_socket() -> io::Result<OwnedFd> {
    let fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            libc::NETLINK_ROUTE,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let socket = unsafe { OwnedFd::from_raw_fd(fd) };
    let receive_bytes: libc::c_int = 256 * 1024;
    let _ = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            (&raw const receive_bytes).cast(),
            std::mem::size_of_val(&receive_bytes) as libc::socklen_t,
        )
    };
    let mut local = unsafe { std::mem::zeroed::<libc::sockaddr_nl>() };
    local.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    local.nl_groups = libc::RTMGRP_TC as u32;
    let bound = unsafe {
        libc::bind(
            socket.as_raw_fd(),
            (&raw const local).cast(),
            std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    };
    if bound < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(socket)
}

fn datagram_has_expected_tc_change(bytes: &[u8], expected_ifindices: &[i32]) -> Result<bool, ()> {
    let mut offset = 0usize;
    let mut changed = false;
    while offset < bytes.len() {
        let remaining = &bytes[offset..];
        if remaining.len() < NETLINK_HEADER_LEN {
            return Err(());
        }
        let length = native_u32(&remaining[0..4])? as usize;
        if length < NETLINK_HEADER_LEN || length > remaining.len() {
            return Err(());
        }
        let message_type = native_u16(&remaining[4..6])?;
        if matches!(
            message_type,
            value if value == libc::NLMSG_ERROR as u16 || value == libc::NLMSG_OVERRUN as u16
        ) {
            return Err(());
        }
        if matches!(
            message_type,
            libc::RTM_NEWQDISC | libc::RTM_DELQDISC | libc::RTM_NEWTFILTER | libc::RTM_DELTFILTER
        ) {
            let payload = &remaining[NETLINK_HEADER_LEN..length];
            if payload.len() < TCMSG_MIN_LEN {
                return Err(());
            }
            let ifindex = native_i32(
                &payload[TCMSG_IFINDEX_OFFSET..TCMSG_IFINDEX_OFFSET + std::mem::size_of::<i32>()],
            )?;
            changed |= expected_ifindices.contains(&ifindex);
        }

        if length == remaining.len() {
            break;
        }
        let aligned = length.checked_add(3).ok_or(())? & !3;
        if aligned > remaining.len() {
            return Err(());
        }
        offset = offset.checked_add(aligned).ok_or(())?;
    }
    Ok(changed)
}

fn native_u16(bytes: &[u8]) -> Result<u16, ()> {
    Ok(u16::from_ne_bytes(bytes.try_into().map_err(|_| ())?))
}

fn native_u32(bytes: &[u8]) -> Result<u32, ()> {
    Ok(u32::from_ne_bytes(bytes.try_into().map_err(|_| ())?))
}

fn native_i32(bytes: &[u8]) -> Result<i32, ()> {
    Ok(i32::from_ne_bytes(bytes.try_into().map_err(|_| ())?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(message_type: u16, ifindex: i32) -> Vec<u8> {
        let length = NETLINK_HEADER_LEN + 20;
        let mut bytes = vec![0u8; length];
        bytes[0..4].copy_from_slice(&(length as u32).to_ne_bytes());
        bytes[4..6].copy_from_slice(&message_type.to_ne_bytes());
        bytes[NETLINK_HEADER_LEN + TCMSG_IFINDEX_OFFSET
            ..NETLINK_HEADER_LEN + TCMSG_IFINDEX_OFFSET + 4]
            .copy_from_slice(&ifindex.to_ne_bytes());
        bytes
    }

    #[test]
    fn matches_only_expected_interfaces_and_tc_message_types() {
        assert_eq!(
            datagram_has_expected_tc_change(&message(libc::RTM_DELTFILTER, 7), &[7]),
            Ok(true)
        );
        assert_eq!(
            datagram_has_expected_tc_change(&message(libc::RTM_NEWQDISC, 8), &[7]),
            Ok(false)
        );
        assert_eq!(
            datagram_has_expected_tc_change(&message(libc::RTM_NEWLINK, 7), &[7]),
            Ok(false)
        );
    }

    #[test]
    fn parses_aligned_multi_message_datagrams() {
        let mut bytes = message(libc::RTM_NEWTFILTER, 9);
        bytes.extend(message(libc::RTM_DELQDISC, 7));
        assert_eq!(datagram_has_expected_tc_change(&bytes, &[7]), Ok(true));
    }

    #[test]
    fn malformed_and_overrun_messages_are_fail_safe() {
        let mut short = message(libc::RTM_NEWTFILTER, 7);
        short[0..4].copy_from_slice(&15u32.to_ne_bytes());
        assert_eq!(datagram_has_expected_tc_change(&short, &[7]), Err(()));
        assert_eq!(
            datagram_has_expected_tc_change(&message(libc::NLMSG_OVERRUN as u16, 7), &[7]),
            Err(())
        );
    }
}
