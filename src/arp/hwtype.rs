//! Hardware type definitions and conversions for ARP
//!
//! Based on net-tools lib/hw.c and linux/if_arp.h
//! Uses hardware type constants from libc

use crate::{NetToolsError, Result};

/// Convert hardware type name to number
/// Matches get_hwtype() from net-tools lib/hw.c
pub fn hwtype_to_num(name: &str) -> Result<u16> {
    match name.to_lowercase().as_str() {
        // Most common types
        "ether" | "ethernet" => Ok(libc::ARPHRD_ETHER),
        "loopback" | "loop" => Ok(libc::ARPHRD_LOOPBACK),

        // Serial line protocols
        "slip" => Ok(libc::ARPHRD_SLIP),
        "cslip" => Ok(libc::ARPHRD_CSLIP),
        "slip6" => Ok(libc::ARPHRD_SLIP6),
        "cslip6" => Ok(libc::ARPHRD_CSLIP6),
        "adaptive" => Ok(libc::ARPHRD_ADAPT),

        // Other network types
        "ppp" => Ok(libc::ARPHRD_PPP),
        "arcnet" => Ok(libc::ARPHRD_ARCNET),
        "pronet" => Ok(libc::ARPHRD_PRONET),
        "ax25" => Ok(libc::ARPHRD_AX25),
        "netrom" => Ok(libc::ARPHRD_NETROM),
        "rose" => Ok(libc::ARPHRD_ROSE),
        "x25" => Ok(libc::ARPHRD_X25),
        "hwx25" => Ok(libc::ARPHRD_HWX25),

        // Token ring
        "tr" | "tokenring" => Ok(libc::ARPHRD_IEEE802),

        // Tunnels
        "tunnel" | "ipip" => Ok(libc::ARPHRD_TUNNEL),
        "sit" => Ok(libc::ARPHRD_SIT),
        "tunnel6" => Ok(libc::ARPHRD_TUNNEL6),

        // HDLC variants
        "hdlc" | "cisco" => Ok(libc::ARPHRD_HDLC),
        "lapb" => Ok(libc::ARPHRD_LAPB),
        "rawhdlc" => Ok(libc::ARPHRD_RAWHDLC),

        // Frame relay
        "dlci" => Ok(libc::ARPHRD_DLCI),
        "frad" => Ok(libc::ARPHRD_FRAD),

        // High-speed networks
        "fddi" => Ok(libc::ARPHRD_FDDI),
        "hippi" => Ok(libc::ARPHRD_HIPPI),
        "ib" | "infiniband" => Ok(libc::ARPHRD_INFINIBAND),

        // Other
        "ash" => Ok(libc::ARPHRD_ASH),
        "irda" => Ok(libc::ARPHRD_IRDA),
        "econet" | "ec" => Ok(libc::ARPHRD_ECONET),
        "eui64" => Ok(libc::ARPHRD_EUI64),
        "strip" => Ok(libc::ARPHRD_METRICOM),
        "atm" => Ok(libc::ARPHRD_ATM),
        "ieee1394" | "firewire" => Ok(libc::ARPHRD_IEEE1394),
        "can" => Ok(libc::ARPHRD_CAN),

        _ => Err(NetToolsError::Other(format!(
            "arp: {}: unknown hardware type.",
            name
        ))),
    }
}

/// Convert hardware type number to name
/// Matches get_hwntype() from net-tools lib/hw.c
pub fn hwtype_num_to_name(num: u16) -> &'static str {
    match num {
        libc::ARPHRD_NETROM => "netrom",
        libc::ARPHRD_ETHER => "ether",
        libc::ARPHRD_EETHER => "eether",
        libc::ARPHRD_AX25 => "ax25",
        libc::ARPHRD_PRONET => "pronet",
        libc::ARPHRD_CHAOS => "chaos",
        libc::ARPHRD_IEEE802 => "tr",
        libc::ARPHRD_ARCNET => "arcnet",
        libc::ARPHRD_APPLETLK => "atalk",
        libc::ARPHRD_DLCI => "dlci",
        libc::ARPHRD_ATM => "atm",
        libc::ARPHRD_METRICOM => "strip",
        libc::ARPHRD_IEEE1394 => "ieee1394",
        libc::ARPHRD_EUI64 => "eui64",
        libc::ARPHRD_INFINIBAND => "infiniband",
        libc::ARPHRD_SLIP => "slip",
        libc::ARPHRD_CSLIP => "cslip",
        libc::ARPHRD_SLIP6 => "slip6",
        libc::ARPHRD_CSLIP6 => "cslip6",
        libc::ARPHRD_RSRVD => "rsrvd",
        libc::ARPHRD_ADAPT => "adaptive",
        libc::ARPHRD_ROSE => "rose",
        libc::ARPHRD_X25 => "x25",
        libc::ARPHRD_HWX25 => "hwx25",
        libc::ARPHRD_CAN => "can",
        libc::ARPHRD_PPP => "ppp",
        libc::ARPHRD_HDLC => "hdlc",
        libc::ARPHRD_LAPB => "lapb",
        libc::ARPHRD_DDCMP => "ddcmp",
        libc::ARPHRD_RAWHDLC => "rawhdlc",
        libc::ARPHRD_TUNNEL => "tunnel",
        libc::ARPHRD_TUNNEL6 => "tunnel6",
        libc::ARPHRD_FRAD => "frad",
        libc::ARPHRD_SKIP => "skip",
        libc::ARPHRD_LOOPBACK => "loop",
        libc::ARPHRD_LOCALTLK => "ltalk",
        libc::ARPHRD_FDDI => "fddi",
        libc::ARPHRD_BIF => "bif",
        libc::ARPHRD_SIT => "sit",
        libc::ARPHRD_IPDDP => "ipddp",
        libc::ARPHRD_IPGRE => "ipgre",
        libc::ARPHRD_PIMREG => "pimreg",
        libc::ARPHRD_HIPPI => "hippi",
        libc::ARPHRD_ASH => "ash",
        libc::ARPHRD_ECONET => "econet",
        libc::ARPHRD_IRDA => "irda",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hwtype_to_num() {
        assert_eq!(hwtype_to_num("ether").unwrap(), libc::ARPHRD_ETHER);
        assert_eq!(hwtype_to_num("ethernet").unwrap(), libc::ARPHRD_ETHER);
        assert_eq!(hwtype_to_num("ETHER").unwrap(), libc::ARPHRD_ETHER);
        assert_eq!(hwtype_to_num("arcnet").unwrap(), libc::ARPHRD_ARCNET);
        assert_eq!(hwtype_to_num("ppp").unwrap(), libc::ARPHRD_PPP);
        assert_eq!(hwtype_to_num("loopback").unwrap(), libc::ARPHRD_LOOPBACK);
        assert!(hwtype_to_num("invalid").is_err());
    }

    #[test]
    fn test_hwtype_num_to_name() {
        assert_eq!(hwtype_num_to_name(libc::ARPHRD_ETHER), "ether");
        assert_eq!(hwtype_num_to_name(libc::ARPHRD_ARCNET), "arcnet");
        assert_eq!(hwtype_num_to_name(libc::ARPHRD_PPP), "ppp");
        assert_eq!(hwtype_num_to_name(libc::ARPHRD_LOOPBACK), "loop");
        assert_eq!(hwtype_num_to_name(9999), "unknown");
    }

    #[test]
    fn test_roundtrip() {
        let types = vec!["ether", "arcnet", "ppp", "fddi", "hippi"];
        for name in types {
            let num = hwtype_to_num(name).unwrap();
            let back = hwtype_num_to_name(num);
            assert_eq!(back, name);
        }
    }
}
