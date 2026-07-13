use crate::{DIR_RX, DIR_TX};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameAccounting {
    pub bytes: u64,
    pub packets: u64,
}

pub const fn tc_frame_accounting(
    direction: u8,
    frame_len: u32,
    wire_len: u32,
    gso_segs: u32,
    ingress_header_len: Option<u16>,
) -> FrameAccounting {
    let (bytes, packets) = if direction == DIR_RX {
        (
            if wire_len > frame_len {
                wire_len as u64
            } else {
                frame_len as u64
            },
            if gso_segs == 0 { 1 } else { gso_segs as u64 },
        )
    } else if direction == DIR_TX && gso_segs > 1 {
        match ingress_header_len {
            Some(header_len) if header_len != 0 => (
                frame_len as u64 + (gso_segs - 1) as u64 * header_len as u64,
                gso_segs as u64,
            ),
            _ => (frame_len as u64, 1),
        }
    } else {
        (frame_len as u64, 1)
    };

    FrameAccounting { bytes, packets }
}
