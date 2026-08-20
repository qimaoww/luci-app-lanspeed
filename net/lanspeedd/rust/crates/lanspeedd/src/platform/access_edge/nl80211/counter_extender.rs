//! Monotonic extension for NL80211 station counters.
//!
//! Some Qualcomm Wi-Fi drivers expose only the 32-bit station byte
//! attributes. At high throughput those counters wrap every few dozen
//! seconds. Treating the wrap as a station reset changes the attachment
//! generation and forces every rate owner to warm up again. Extend only an
//! unambiguous high-to-low wrap; other decreases remain fail-closed resets.

use crate::platform::access_edge::rate::LinkCounters;

use super::StationByteCounterWidth;

const COUNTER32_MODULUS: u64 = 1_u64 << 32;
const COUNTER32_WRAP_HIGH_WATERMARK: u64 = COUNTER32_MODULUS * 3 / 4;
const COUNTER32_WRAP_LOW_WATERMARK: u64 = COUNTER32_MODULUS / 4;

pub(super) fn extend_station_counters(
    previous_raw: LinkCounters,
    current_raw: LinkCounters,
    previous_extended: LinkCounters,
    rx_byte_width: StationByteCounterWidth,
    tx_byte_width: StationByteCounterWidth,
) -> Option<LinkCounters> {
    Some(LinkCounters {
        rx_bytes: previous_extended.rx_bytes.checked_add(counter_delta(
            previous_raw.rx_bytes,
            current_raw.rx_bytes,
            rx_byte_width,
        )?)?,
        tx_bytes: previous_extended.tx_bytes.checked_add(counter_delta(
            previous_raw.tx_bytes,
            current_raw.tx_bytes,
            tx_byte_width,
        )?)?,
        // NL80211_STA_INFO_{RX,TX}_PACKETS are u32 attributes even when the
        // corresponding byte attributes are 64-bit.
        rx_packets: previous_extended.rx_packets.checked_add(counter_delta(
            previous_raw.rx_packets,
            current_raw.rx_packets,
            StationByteCounterWidth::Bits32,
        )?)?,
        tx_packets: previous_extended.tx_packets.checked_add(counter_delta(
            previous_raw.tx_packets,
            current_raw.tx_packets,
            StationByteCounterWidth::Bits32,
        )?)?,
    })
}

fn counter_delta(previous: u64, current: u64, width: StationByteCounterWidth) -> Option<u64> {
    if current >= previous {
        return current.checked_sub(previous);
    }
    if width == StationByteCounterWidth::Bits32
        && previous < COUNTER32_MODULUS
        && current < COUNTER32_MODULUS
        && previous >= COUNTER32_WRAP_HIGH_WATERMARK
        && current <= COUNTER32_WRAP_LOW_WATERMARK
    {
        return COUNTER32_MODULUS
            .checked_sub(previous)
            .and_then(|remaining| remaining.checked_add(current));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::{counter_delta, extend_station_counters};
    use crate::platform::access_edge::{nl80211::StationByteCounterWidth, rate::LinkCounters};

    #[test]
    fn extends_an_unambiguous_32_bit_wrap() {
        let previous_raw = LinkCounters {
            rx_bytes: u64::from(u32::MAX) - 99,
            tx_bytes: 500,
            rx_packets: 1_000,
            tx_packets: 2_000,
        };
        let current_raw = LinkCounters {
            rx_bytes: 100,
            tx_bytes: 700,
            rx_packets: 1_100,
            tx_packets: 2_100,
        };
        let extended = extend_station_counters(
            previous_raw,
            current_raw,
            previous_raw,
            StationByteCounterWidth::Bits32,
            StationByteCounterWidth::Bits32,
        )
        .expect("32-bit wrap is continuous");
        assert_eq!(extended.rx_bytes, u64::from(u32::MAX) + 101);
        assert_eq!(extended.tx_bytes, 700);
        assert_eq!(extended.rx_packets, 1_100);
        assert_eq!(extended.tx_packets, 2_100);
    }

    #[test]
    fn rejects_a_64_bit_decrease_and_a_non_wrap_32_bit_decrease() {
        assert_eq!(
            counter_delta(10_000, 100, StationByteCounterWidth::Bits64),
            None
        );
        assert_eq!(
            counter_delta(2_000_000_000, 100, StationByteCounterWidth::Bits32),
            None
        );
    }

    #[test]
    fn extends_a_32_bit_packet_wrap_independently_of_64_bit_bytes() {
        let previous_raw = LinkCounters {
            rx_bytes: 10_000,
            tx_bytes: 20_000,
            rx_packets: u64::from(u32::MAX) - 9,
            tx_packets: 200,
        };
        let current_raw = LinkCounters {
            rx_bytes: 11_000,
            tx_bytes: 22_000,
            rx_packets: 20,
            tx_packets: 220,
        };
        let extended = extend_station_counters(
            previous_raw,
            current_raw,
            previous_raw,
            StationByteCounterWidth::Bits64,
            StationByteCounterWidth::Bits64,
        )
        .expect("packet wrap is continuous");
        assert_eq!(extended.rx_packets, u64::from(u32::MAX) + 21);
        assert_eq!(extended.rx_bytes, 11_000);
        assert_eq!(extended.tx_bytes, 22_000);
    }
}
