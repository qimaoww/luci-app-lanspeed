#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dhcp_host_name_uses_mac_without_requiring_ip() {
        let mut cache = HostnameCache::with_capacity(8);
        cache.parse_dhcp_config(
            "config host 'cfg01'\n\toption mac '52:C4:FD:3F:36:EF'\n\toption name 'nas'\n",
        );
        assert_eq!(cache.lookup("52:c4:fd:3f:36:ef", &[]), Some("nas"));
    }

    #[test]
    fn dhcp_host_name_overrides_lease_name_for_mac_and_ip() {
        let mut cache = HostnameCache::with_capacity(8);
        cache.parse_leases("123 52:c4:fd:3f:36:ef 192.0.2.10 lease-name *\n");
        cache.parse_dhcp_config(
            "config host 'cfg01'\n\toption mac '52:C4:FD:3F:36:EF'\n\toption ip '192.0.2.10'\n\toption name 'custom-name'\n",
        );
        assert_eq!(cache.lookup("52:c4:fd:3f:36:ef", &[]), Some("custom-name"));
        assert_eq!(
            cache.lookup("00:11:22:33:44:55", &["192.0.2.10"]),
            Some("custom-name")
        );
    }

    #[test]
    fn dhcp_host_name_applies_to_each_mac_in_a_list() {
        let mut cache = HostnameCache::with_capacity(8);
        cache.parse_dhcp_config(
            "config host 'cfg01'\n\tlist mac '52:c4:fd:3f:36:ef'\n\tlist mac 'fe:25:75:2b:70:7d'\n\toption name 'nas'\n",
        );
        assert_eq!(cache.lookup("fe:25:75:2b:70:7d", &[]), Some("nas"));
    }
}
