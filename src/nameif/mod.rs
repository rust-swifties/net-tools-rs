//! Rust implementation of the nameif command from net-tools

use crate::{NetToolsError, RELEASE, Result};
use clap::Parser;
use std::fs;
use std::net::UdpSocket;
use std::os::unix::io::AsRawFd;

const IFNAMEIZ: usize = 16; // Linux ifname max len
const IFR_SA_DATA_LEN: usize = 14; // sizeof(ifreq.ifr_hwaddr.sa_data)

#[derive(Parser, Debug)]
#[command(
    name = "nameif",
    version = RELEASE,
    about = "name network interfaces based on MAC addresses",
    long_about = "Rust implementation of the nameif command.\n\n\
                  nameif renames network interfaces based on MAC addresses. When no arguments \
                  are given /etc/mactab is read. Each line of it contains an interface name \
                  and a Ethernet MAC address. Comments are allowed starting with #. Otherwise \
                  the interfaces specified on the command line are processed. nameif looks for \
                  the interface with the given MAC address and renames it to the name given.\n\n\
                  nameif should be run before the interface is up, otherwise it'll fail."
)]
struct Args {
    /// Configuration file (default: /etc/mactab)
    #[arg(short = 'c', long = "config-file", default_value = "/etc/mactab")]
    config_file: String,

    /// Interface name and MAC address pairs (ifname macaddress)
    #[arg(value_name = "IFNAME MACADDRESS")]
    pairs: Vec<String>,
}

#[derive(Debug, Clone)]
struct InterfaceChange {
    ifname: String,
    mac: Vec<u8>,
    mac_len: usize,
    found: bool,
}

pub fn main() {
    let args = Args::parse();

    let mut changes = match parse_cli_pairs(&args.pairs) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("nameif: {e}");
            std::process::exit(1);
        }
    };

    if changes.is_empty() || args.config_file != "/etc/mactab" {
        match read_config_file(&args.config_file) {
            Ok(mut config_changes) => changes.append(&mut config_changes),
            Err(e) => {
                eprintln!("nameif: {e}");
                std::process::exit(1);
            }
        }
    }

    let interfaces = match list_interfaces() {
        Ok(i) => i,
        Err(e) => {
            eprintln!("nameif: {e}");
            std::process::exit(1);
        }
    };

    for ifname in interfaces {
        let mac = match get_interface_mac(&ifname) {
            Ok(m) => m,
            Err(_) => continue,
        };

        if let Some(change) = changes
            .iter_mut()
            .find(|ch| mac.len() >= ch.mac_len && ch.mac[..ch.mac_len] == mac[..ch.mac_len])
        {
            change.found = true;

            if ifname != change.ifname
                && let Err(e) = rename_interface(&ifname, &change.ifname)
            {
                eprintln!("nameif: {e}");
                std::process::exit(1);
            }
        }
    }

    let mut has_missing = false;
    for change in &changes {
        if !change.found {
            eprintln!("nameif: interface '{}' not found", change.ifname);
            has_missing = true;
        }
    }

    if has_missing {
        std::process::exit(1);
    }
}

/// Copy bytes from a &[u8] slice to a [i8] array
/// This is a safe alternative to pointer casting
/// Converts u8 to i8 because C-style character arrays (like ifr_name) use signed char,
/// even though the underlying bytes are identical in memory representation
fn copy_bytes_to_i8_array(dest: &mut [i8], src: &[u8]) {
    let len = src.len().min(dest.len());
    for i in 0..len {
        dest[i] = src[i] as i8;
    }
}

/// Parse MAC address from string format "00:11:22:33:44:55" to bytes
fn parse_mac(s: &str) -> Result<Vec<u8>> {
    let mut mac = Vec::new();

    for part in s.split(':') {
        let byte = u8::from_str_radix(part, 16)
            .map_err(|_| NetToolsError::InvalidArgument(format!("cannot parse MAC '{s}'")))?;
        mac.push(byte);

        if mac.len() > IFR_SA_DATA_LEN {
            return Err(NetToolsError::Other(format!(
                "MAC address '{s}' is larger than maximum allowed {IFR_SA_DATA_LEN} bytes"
            )));
        }
    }

    if mac.is_empty() {
        return Err(NetToolsError::InvalidArgument(
            "empty MAC address".to_string(),
        ));
    }

    Ok(mac)
}

/// Read and parse the config file
fn read_config_file(path: &str) -> Result<Vec<InterfaceChange>> {
    let contents = fs::read_to_string(path)
        .map_err(|e| NetToolsError::Other(format!("opening configuration file {path}: {e}")))?;

    let mut changes = Vec::new();

    for (line_num, line) in contents.lines().enumerate() {
        let line_num = line_num + 1;

        // Resolve comments
        let line = if let Some(pos) = line.find('#') {
            &line[..pos]
        } else {
            line
        };

        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() != 2 {
            return Err(NetToolsError::InvalidArgument(format!(
                "invalid format at line {line_num}: expected 'ifname macaddress'"
            )));
        }

        let ifname = parts[0];
        let mac_str = parts[1];

        if ifname.len() >= IFNAMEIZ {
            return Err(NetToolsError::NameTooLong(format!(
                "interface name too long at line {line_num}"
            )));
        }

        if ifname.contains(':') {
            eprintln!(
                "nameif: warning: alias device {} at line {} probably has no mac",
                ifname, line_num
            );
        }

        let mac = parse_mac(mac_str)
            .map_err(|e| NetToolsError::InvalidArgument(format!("at line {line_num}: {e}")))?;

        let mac_len = mac.len();
        changes.push(InterfaceChange {
            ifname: ifname.to_string(),
            mac,
            mac_len,
            found: false,
        })
    }

    Ok(changes)
}

/// Parse command-line interface/MAC pairs
fn parse_cli_pairs(pairs: &[String]) -> Result<Vec<InterfaceChange>> {
    if !pairs.len().is_multiple_of(2) {
        return Err(NetToolsError::InvalidArgument(
            "interface name and MAC address must be provided in pairs".to_string(),
        ));
    }

    let mut changes = Vec::new();
    let mut i = 0;
    while i < pairs.len() {
        let ifname = &pairs[i];
        let mac_str = &pairs[i + 1];

        if ifname.len() >= IFNAMEIZ {
            return Err(NetToolsError::NameTooLong(format!(
                "interface name '{}' is too long (max {} chars)",
                ifname,
                IFNAMEIZ - 1
            )));
        }

        let mac = parse_mac(mac_str)?;
        let mac_len = mac.len();
        changes.push(InterfaceChange {
            ifname: ifname.clone(),
            mac,
            mac_len,
            found: false,
        });

        i += 2;
    }

    Ok(changes)
}

/// List all network interfaces from /proc/net/dev
fn list_interfaces() -> Result<Vec<String>> {
    let contents = fs::read_to_string("/proc/net/dev")
        .map_err(|e| NetToolsError::Other(format!("open of /proc/net/dev: {e}")))?;

    let mut interfaces = Vec::new();

    for (line_num, line) in contents.lines().enumerate() {
        // Skip the header lines
        if line_num < 2 {
            continue;
        }

        let line = line.trim();

        // Interface name is before :, for example `wlp1s0:`
        if let Some(pos) = line.find(':') {
            let ifname = line[..pos].trim();

            if ifname.len() >= IFNAMEIZ {
                continue;
            }

            interfaces.push(ifname.to_string());
        }
    }

    Ok(interfaces)
}

/// Get the MAC address of a network interface
fn get_interface_mac(ifname: &str) -> Result<Vec<u8>> {
    let socket = UdpSocket::bind("0.0.0.0:0")
        .map_err(|e| NetToolsError::Other(format!("socket creation failed: {e}")))?;

    let ifname_bytes = ifname.as_bytes();
    if ifname_bytes.len() >= libc::IF_NAMESIZE {
        return Err(NetToolsError::NameTooLong(format!(
            "interface name '{ifname}' too long"
        )));
    }

    let mut ifreq = libc::ifreq {
        ifr_name: [0; libc::IF_NAMESIZE],
        ifr_ifru: libc::__c_anonymous_ifr_ifru {
            ifru_addr: libc::sockaddr {
                sa_family: 0,
                sa_data: [0; 14],
            },
        },
    };

    copy_bytes_to_i8_array(&mut ifreq.ifr_name, ifname_bytes);

    // SAFETY: Valid fd and properly initialized ifreq struct for SIOCGIFHWADDR
    let ret = unsafe { libc::ioctl(socket.as_raw_fd(), libc::SIOCGIFHWADDR, &mut ifreq) };

    if ret < 0 {
        let errno = std::io::Error::last_os_error();
        return Err(NetToolsError::Other(format!(
            "ioctl SIOCGIFHWADDR failed for interface '{ifname}': {errno}",
        )));
    }

    // SAFETY: Reading ifru_hwaddr which was just populated by the successful ioctl
    let mac = unsafe {
        let sa_data = &ifreq.ifr_ifru.ifru_hwaddr.sa_data;
        sa_data[..IFR_SA_DATA_LEN]
            .iter()
            .map(|&b| b as u8)
            .collect()
    };

    Ok(mac)
}

/// Rename a network interface
fn rename_interface(old_name: &str, new_name: &str) -> Result<()> {
    let socket = UdpSocket::bind("0.0.0.0:0")
        .map_err(|e| NetToolsError::Other(format!("socket creation failed: {e}")))?;

    let old_bytes = old_name.as_bytes();
    if old_bytes.len() >= libc::IF_NAMESIZE {
        return Err(NetToolsError::NameTooLong(format!(
            "interface name '{old_name}' too long"
        )));
    }

    let new_bytes = new_name.as_bytes();
    if new_bytes.len() >= libc::IF_NAMESIZE {
        return Err(NetToolsError::NameTooLong(format!(
            "interface name '{new_name}' too long"
        )));
    }

    let mut ifreq = libc::ifreq {
        ifr_name: [0; libc::IF_NAMESIZE],
        ifr_ifru: libc::__c_anonymous_ifr_ifru {
            ifru_newname: [0; libc::IF_NAMESIZE],
        },
    };

    copy_bytes_to_i8_array(&mut ifreq.ifr_name, old_bytes);

    // SAFETY: We initialized this union variant and are writing to it, not reading uninitialized data
    let newname_slice = unsafe { &mut ifreq.ifr_ifru.ifru_newname };
    copy_bytes_to_i8_array(newname_slice, new_bytes);

    // SAFETY: Valid fd with properly initialized ifreq containing old and new interface names
    let ret = unsafe { libc::ioctl(socket.as_raw_fd(), libc::SIOCSIFNAME, &ifreq) };

    if ret < 0 {
        let errno = std::io::Error::last_os_error();
        return Err(NetToolsError::Other(format!(
            "cannot change name of {old_name} to {new_name}: {errno}"
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_mac_valid() {
        let mac = parse_mac("00:11:22:33:44:55").unwrap();
        assert_eq!(mac, vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    }

    #[test]
    fn test_parse_mac_lowercase() {
        let mac = parse_mac("aa:bb:cc:dd:ee:ff").unwrap();
        assert_eq!(mac, vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    }

    #[test]
    fn test_parse_mac_mixed_case() {
        let mac = parse_mac("Aa:Bb:Cc:Dd:Ee:Ff").unwrap();
        assert_eq!(mac, vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    }

    #[test]
    fn test_parse_mac_invalid() {
        assert!(parse_mac("not:a:mac").is_err());
        assert!(parse_mac("00:11:22:33:44:GG").is_err());
        assert!(parse_mac("").is_err());
    }

    #[test]
    fn test_parse_mac_single_byte() {
        let mac = parse_mac("ff").unwrap();
        assert_eq!(mac, vec![0xff]);
    }

    #[test]
    fn test_parse_mac_two_bytes() {
        let mac = parse_mac("00:11").unwrap();
        assert_eq!(mac, vec![0x00, 0x11]);
    }

    #[test]
    fn test_parse_cli_pairs_valid() {
        let pairs = vec!["eth0".to_string(), "00:11:22:33:44:55".to_string()];
        let changes = parse_cli_pairs(&pairs).unwrap();
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].ifname, "eth0");
        assert_eq!(changes[0].mac, vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        assert!(!changes[0].found);
    }

    #[test]
    fn test_parse_cli_pairs_multiple() {
        let pairs = vec![
            "eth0".to_string(),
            "00:11:22:33:44:55".to_string(),
            "eth1".to_string(),
            "aa:bb:cc:dd:ee:ff".to_string(),
        ];
        let changes = parse_cli_pairs(&pairs).unwrap();
        assert_eq!(changes.len(), 2);
        assert_eq!(changes[0].ifname, "eth0");
        assert_eq!(changes[1].ifname, "eth1");
    }

    #[test]
    fn test_parse_cli_pairs_odd_number() {
        let pairs = vec!["eth0".to_string()];
        assert!(parse_cli_pairs(&pairs).is_err());
    }

    #[test]
    fn test_parse_cli_pairs_empty() {
        let pairs = vec![];
        let changes = parse_cli_pairs(&pairs).unwrap();
        assert_eq!(changes.len(), 0);
    }

    #[test]
    fn test_parse_cli_pairs_name_too_long() {
        let long_name = "a".repeat(20);
        let pairs = vec![long_name, "00:11:22:33:44:55".to_string()];
        assert!(parse_cli_pairs(&pairs).is_err());
    }

    #[test]
    fn test_parse_cli_pairs_invalid_mac() {
        let pairs = vec!["eth0".to_string(), "invalid".to_string()];
        assert!(parse_cli_pairs(&pairs).is_err());
    }

    #[test]
    fn test_list_interfaces() {
        let interfaces = list_interfaces().unwrap();
        assert!(!interfaces.is_empty());
        assert!(interfaces.iter().any(|i| i == "lo"));
    }

    #[test]
    fn test_get_interface_mac_loopback() {
        // We don't assert success because loopback might not have a MAC
        // but we at least test that the function runs
        let _ = get_interface_mac("lo");
    }

    #[test]
    fn test_get_interface_mac_nonexistent() {
        let result = get_interface_mac("this_interface_does_not_exist_12345");
        assert!(result.is_err());
    }
}
