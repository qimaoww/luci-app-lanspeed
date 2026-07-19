use super::TcFilter;

pub const LANSPEED_PREF: u32 = 49_152;
pub const LANSPEED_HANDLE: &str = "0x1eed";
pub const LANSPEED_EARLY_PREF: u32 = 1;
pub const LANSPEED_EARLY_HANDLE: &str = "0x1eee";

pub fn has_owned_identity_collision(filters: &[TcFilter]) -> bool {
    filters.iter().any(|filter| {
        filter.owner != "lanspeed"
            && ((filter.pref == LANSPEED_PREF && normalized_handle(&filter.handle) == "1eed")
                || (filter.pref == LANSPEED_EARLY_PREF
                    && normalized_handle(&filter.handle) == "1eee"))
    })
}

pub fn has_foreign_filters(filters: &[TcFilter]) -> bool {
    filters.iter().any(|filter| filter.owner != "lanspeed")
}

pub fn dae_preempts_lan_ingress(filters: &[TcFilter], attach_ifnames: &[String]) -> bool {
    filters.iter().any(|filter| {
        filter.owner == "dae"
            && filter.direction == "ingress"
            && filter.pref > 0
            && filter.pref < LANSPEED_PREF
            && attach_ifnames
                .iter()
                .any(|ifname| ifname == &filter.interface)
    })
}

pub fn parse_filter_lines(interface: &str, direction: &str, output: &str) -> Vec<TcFilter> {
    let mut filters = Vec::new();
    let mut summary = None;

    for line in output
        .lines()
        .filter(|line| line.contains("filter") || line.contains(" bpf "))
    {
        let parsed = TcFilter {
            interface: interface.into(),
            direction: direction.into(),
            pref: token_after(line, "pref ")
                .and_then(|value| value.parse().ok())
                .unwrap_or_default(),
            handle: token_after(line, "handle ").unwrap_or("unknown").into(),
            owner: owner(line).into(),
            source: "tc_filter_show".into(),
        };

        if filter_detail(line) {
            if summary
                .as_ref()
                .is_some_and(|item: &TcFilter| item.pref == parsed.pref)
            {
                summary = None;
            } else if let Some(item) = summary.take() {
                filters.push(item);
            }
            filters.push(parsed);
        } else if let Some(item) = summary.replace(parsed) {
            filters.push(item);
        }
    }

    if let Some(item) = summary {
        filters.push(item);
    }
    filters
}

fn filter_detail(line: &str) -> bool {
    token_after(line, "handle ").is_some()
        || token_after(line, "fh ").is_some()
        || owner(line) != "unknown"
}

fn token_after<'a>(line: &'a str, marker: &str) -> Option<&'a str> {
    line.split_once(marker)?.1.split_whitespace().next()
}

fn normalized_handle(handle: &str) -> &str {
    handle.strip_prefix("0x").unwrap_or(handle)
}

fn owner(line: &str) -> &'static str {
    if line.contains("lanspeed_ingres") || line.contains("lanspeed_egress") {
        "lanspeed"
    } else if line.contains("dae") || line.contains("daed") || line.contains("dae0") {
        "dae"
    } else if line.contains("sqm") {
        "sqm"
    } else if line.contains("qosify") {
        "qosify"
    } else if line.contains("ifb") {
        "ifb"
    } else {
        "unknown"
    }
}
