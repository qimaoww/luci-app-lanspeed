#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TrafficCounters {
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub tx_packets: u64,
    pub rx_packets: u64,
}

impl TrafficCounters {
    pub fn fcs_normalized(self) -> Option<Self> {
        Some(Self {
            tx_bytes: self.tx_bytes.checked_add(self.tx_packets.checked_mul(4)?)?,
            rx_bytes: self.rx_bytes.checked_add(self.rx_packets.checked_mul(4)?)?,
            ..self
        })
    }
}
