//! Functions for manipulating arpreq structures

use crate::{NetToolsError, Result};
use std::mem;
use std::net::Ipv4Addr;

/// Parsed options for setting an ARP entry
#[derive(Debug)]
pub(super) struct ArpSetOptions {
    pub host: String,
    pub mac: String,
    pub use_device: bool,
    pub device: Option<String>,
    pub netmask: Option<String>,
    pub flags: libc::c_int,
}

/// Parse command-line arguments for arp -s
pub(super) fn parse_set_args(
    args: &[String],
    use_device: bool,
    initial_device: Option<String>,
) -> Result<ArpSetOptions> {
    if args.is_empty() {
        return Err(NetToolsError::Other("arp: need host name".to_string()));
    }
    if args.len() < 2 && !use_device {
        return Err(NetToolsError::Other(
            "arp: need hardware address".to_string(),
        ));
    }

    let host = args[0].clone();
    let mut flags = libc::ATF_PERM | libc::ATF_COM;
    let mut device = initial_device;
    let mut netmask: Option<String> = None;
    let mac: String;

    // Get MAC address (either from argument or from device)
    if use_device {
        if args.len() < 2 {
            return Err(NetToolsError::Other("arp: need device name".to_string()));
        }
        device = Some(args[1].clone());
        mac = String::new(); // Will be filled from device
    } else {
        mac = args[1].clone();
    }

    // Parsing additional arguments
    // Start with index 2 because the first two arguments were already handled
    let mut arg_idx = 2;
    while arg_idx < args.len() {
        match args[arg_idx].as_str() {
            "pub" => flags |= libc::ATF_PUBL,
            "priv" => flags &= !libc::ATF_PUBL,
            "temp" => flags &= !libc::ATF_PERM,
            "trail" => flags |= libc::ATF_USETRAILERS,
            "dontpub" => flags |= libc::ATF_DONTPUB,
            "auto" => flags |= libc::ATF_MAGIC,
            "netmask" => {
                arg_idx += 1;
                if arg_idx >= args.len() {
                    return Err(NetToolsError::Other("arp: need netmask value".to_string()));
                }
                netmask = Some(args[arg_idx].clone());
            }
            "dev" => {
                arg_idx += 1;
                if arg_idx >= args.len() {
                    return Err(NetToolsError::Other("arp: need device name".to_string()));
                }
                device = Some(args[arg_idx].clone());
            }
            _ => {
                return Err(NetToolsError::Other(format!(
                    "arp: invalid argument: {}",
                    args[arg_idx]
                )));
            }
        }
        arg_idx += 1;
    }

    Ok(ArpSetOptions {
        host,
        mac,
        use_device,
        device,
        netmask,
        flags,
    })
}

/// Set IP address in arpreq structure
pub(super) fn set_ip(req: &mut libc::arpreq, ip: &str) -> Result<()> {
    let ip_addr: Ipv4Addr = ip
        .parse()
        .map_err(|_| NetToolsError::Other(format!("arp: invalid IP address: {}", ip)))?;

    // SAFETY: Casting to sockaddr_in to set IP address
    let sa = unsafe { &mut *(&mut req.arp_pa as *mut libc::sockaddr as *mut libc::sockaddr_in) };
    sa.sin_family = libc::AF_INET as libc::sa_family_t;
    sa.sin_addr.s_addr = u32::from(ip_addr).to_be();

    Ok(())
}

/// Set MAC address in arpreq from a device interface
pub(super) fn set_mac_from_device(
    sockfd: libc::c_int,
    req: &mut libc::arpreq,
    device: &str,
) -> Result<()> {
    // SAFETY: Initialize ifreq structure
    let mut ifr: libc::ifreq = unsafe { mem::zeroed() };
    let dev_bytes = device.as_bytes();
    if dev_bytes.len() >= libc::IFNAMSIZ {
        return Err(NetToolsError::Other(format!(
            "arp: device name too long: {}",
            device
        )));
    }

    // SAFETY: Copy device name to ifreq.ifr_name
    // We've already verified that dev_bytes.len() < IFNAMSIZ, so this won't overflow
    // ifr_name is properly initialized (zeroed) and the pointers are valid
    unsafe {
        std::ptr::copy_nonoverlapping(
            dev_bytes.as_ptr() as *const libc::c_char,
            ifr.ifr_name.as_mut_ptr(),
            dev_bytes.len(),
        );
    }

    // SAFETY: Get hardware address from interface
    let result = unsafe { libc::ioctl(sockfd, libc::SIOCGIFHWADDR as _, &mut ifr) };
    if result < 0 {
        return Err(NetToolsError::Other(format!(
            "arp: cant get HW-Address for `{}': {}.",
            device,
            std::io::Error::last_os_error()
        )));
    }

    // SAFETY: Copy hardware address from ifreq to arpreq
    // Both structures are properly initialized and the union access is valid
    unsafe {
        req.arp_ha = ifr.ifr_ifru.ifru_hwaddr;
    }

    Ok(())
}

/// Set MAC address in arpreq from a MAC address string
pub(super) fn set_mac_from_string(req: &mut libc::arpreq, mac: &str) -> Result<()> {
    let mac_bytes = parse_mac_address(mac)?;

    // SAFETY: Set MAC address in arpreq structure
    let ha = unsafe { &mut *(&mut req.arp_ha as *mut libc::sockaddr) };
    ha.sa_family = libc::ARPHRD_ETHER as libc::sa_family_t;
    // SAFETY: Copy 6 bytes of MAC address to sockaddr sa_data
    // mac_bytes is guaranteed to be 6 bytes, sa_data has at least 14 bytes
    unsafe {
        std::ptr::copy_nonoverlapping(mac_bytes.as_ptr(), ha.sa_data.as_mut_ptr() as *mut u8, 6);
    }

    Ok(())
}

/// Set device name in arpreq structure
pub(super) fn set_device(req: &mut libc::arpreq, device: &str) -> Result<()> {
    let dev_bytes = device.as_bytes();
    if dev_bytes.len() >= libc::IFNAMSIZ {
        return Err(NetToolsError::Other(format!(
            "arp: device name too long: {}",
            device
        )));
    }
    // SAFETY: Casting byte slice to c_char slice for copy
    // Both types are single-byte and the length is preserved
    req.arp_dev[..dev_bytes.len()]
        .copy_from_slice(unsafe { &*(dev_bytes as *const [u8] as *const [libc::c_char]) });
    Ok(())
}

/// Set netmask in arpreq structure
pub(super) fn set_netmask(
    req: &mut libc::arpreq,
    netmask: &str,
    flags: &mut libc::c_int,
) -> Result<()> {
    let mask_addr: Ipv4Addr = netmask
        .parse()
        .map_err(|_| NetToolsError::Other(format!("arp: invalid netmask: {}", netmask)))?;

    // SAFETY: Casting to sockaddr_in to set netmask
    let mask_sa =
        unsafe { &mut *(&mut req.arp_netmask as *mut libc::sockaddr as *mut libc::sockaddr_in) };
    mask_sa.sin_family = libc::AF_INET as libc::sa_family_t;
    mask_sa.sin_addr.s_addr = u32::from(mask_addr).to_be();
    *flags |= libc::ATF_NETMASK;

    Ok(())
}

/// Parse a MAC address string into bytes
fn parse_mac_address(mac: &str) -> Result<[u8; 6]> {
    let parts: Vec<&str> = if mac.contains(':') {
        mac.split(':').collect()
    } else if mac.contains('-') {
        mac.split('-').collect()
    } else {
        return Err(NetToolsError::Other(
            "arp: invalid hardware address".to_string(),
        ));
    };

    if parts.len() != 6 {
        return Err(NetToolsError::Other(
            "arp: invalid hardware address".to_string(),
        ));
    }

    let mut bytes = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        bytes[i] = u8::from_str_radix(part, 16)
            .map_err(|_| NetToolsError::Other("arp: invalid hardware address".to_string()))?;
    }

    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_mac_address_colon() {
        let mac = parse_mac_address("aa:bb:cc:dd:ee:ff").unwrap();
        assert_eq!(mac, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);

        let mac = parse_mac_address("00:11:22:33:44:55").unwrap();
        assert_eq!(mac, [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    }

    #[test]
    fn test_parse_mac_address_dash() {
        let mac = parse_mac_address("aa-bb-cc-dd-ee-ff").unwrap();
        assert_eq!(mac, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    }

    #[test]
    fn test_parse_mac_address_invalid_format() {
        assert!(parse_mac_address("aabbccddeeff").is_err());
        assert!(parse_mac_address("aa:bb:cc:dd:ee").is_err());
        assert!(parse_mac_address("aa:bb:cc:dd:ee:ff:00").is_err());
        assert!(parse_mac_address("gg:bb:cc:dd:ee:ff").is_err());
        assert!(parse_mac_address("").is_err());
    }

    #[test]
    fn test_parse_set_args_basic() {
        let args = vec!["192.168.1.1".to_string(), "aa:bb:cc:dd:ee:ff".to_string()];
        let opts = parse_set_args(&args, false, None).unwrap();
        assert_eq!(opts.host, "192.168.1.1");
        assert_eq!(opts.mac, "aa:bb:cc:dd:ee:ff");
        assert!(!opts.use_device);
        assert_eq!(opts.device, None);
        assert_eq!(opts.netmask, None);
        assert_eq!(opts.flags, libc::ATF_PERM | libc::ATF_COM);
    }

    #[test]
    fn test_parse_set_args_with_flags() {
        let args = vec![
            "192.168.1.1".to_string(),
            "aa:bb:cc:dd:ee:ff".to_string(),
            "pub".to_string(),
            "temp".to_string(),
        ];
        let opts = parse_set_args(&args, false, None).unwrap();
        assert_eq!(opts.host, "192.168.1.1");
        assert_eq!(opts.flags & libc::ATF_PUBL, libc::ATF_PUBL);
        assert_eq!(opts.flags & libc::ATF_PERM, 0); // temp removes PERM
    }

    #[test]
    fn test_parse_set_args_with_device() {
        let args = vec![
            "192.168.1.1".to_string(),
            "aa:bb:cc:dd:ee:ff".to_string(),
            "dev".to_string(),
            "eth0".to_string(),
        ];
        let opts = parse_set_args(&args, false, None).unwrap();
        assert_eq!(opts.device, Some("eth0".to_string()));
    }

    #[test]
    fn test_parse_set_args_with_netmask() {
        let args = vec![
            "192.168.1.1".to_string(),
            "aa:bb:cc:dd:ee:ff".to_string(),
            "netmask".to_string(),
            "255.255.255.0".to_string(),
        ];
        let opts = parse_set_args(&args, false, None).unwrap();
        assert_eq!(opts.netmask, Some("255.255.255.0".to_string()));
    }

    #[test]
    fn test_parse_set_args_use_device() {
        let args = vec!["192.168.1.1".to_string(), "eth0".to_string()];
        let opts = parse_set_args(&args, true, None).unwrap();
        assert_eq!(opts.host, "192.168.1.1");
        assert_eq!(opts.device, Some("eth0".to_string()));
        assert!(opts.use_device);
        assert_eq!(opts.mac, ""); // Empty when using device
    }

    #[test]
    fn test_parse_set_args_missing_host() {
        let args = vec![];
        let result = parse_set_args(&args, false, None);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "arp: need host name");
    }

    #[test]
    fn test_parse_set_args_missing_mac() {
        let args = vec!["192.168.1.1".to_string()];
        let result = parse_set_args(&args, false, None);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "arp: need hardware address"
        );
    }

    #[test]
    fn test_parse_set_args_missing_device() {
        let args = vec!["192.168.1.1".to_string()];
        let result = parse_set_args(&args, true, None);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "arp: need device name");
    }

    #[test]
    fn test_parse_set_args_invalid_argument() {
        let args = vec![
            "192.168.1.1".to_string(),
            "aa:bb:cc:dd:ee:ff".to_string(),
            "invalid_flag".to_string(),
        ];
        let result = parse_set_args(&args, false, None);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("invalid argument"));
    }

    #[test]
    fn test_parse_set_args_missing_netmask_value() {
        let args = vec![
            "192.168.1.1".to_string(),
            "aa:bb:cc:dd:ee:ff".to_string(),
            "netmask".to_string(),
        ];
        let result = parse_set_args(&args, false, None);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "arp: need netmask value");
    }

    #[test]
    fn test_parse_set_args_missing_dev_value() {
        let args = vec![
            "192.168.1.1".to_string(),
            "aa:bb:cc:dd:ee:ff".to_string(),
            "dev".to_string(),
        ];
        let result = parse_set_args(&args, false, None);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "arp: need device name");
    }

    #[test]
    fn test_set_ip_valid() {
        // SAFETY: Initialize arpreq structure with zeros
        let mut req: libc::arpreq = unsafe { mem::zeroed() };
        let result = set_ip(&mut req, "192.168.1.1");
        assert!(result.is_ok());

        // Verify IP was set correctly
        // SAFETY: Reading the sockaddr_in we just set
        let sa = unsafe { &*(&req.arp_pa as *const libc::sockaddr as *const libc::sockaddr_in) };
        assert_eq!(sa.sin_family, libc::AF_INET as libc::sa_family_t);
        let expected_ip: Ipv4Addr = "192.168.1.1".parse().unwrap();
        assert_eq!(sa.sin_addr.s_addr, u32::from(expected_ip).to_be());
    }

    #[test]
    fn test_set_ip_invalid() {
        // SAFETY: Initialize arpreq structure with zeros
        let mut req: libc::arpreq = unsafe { mem::zeroed() };
        let result = set_ip(&mut req, "invalid");
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("invalid IP address")
        );
    }

    #[test]
    fn test_set_device_valid() {
        // SAFETY: Initialize arpreq structure with zeros
        let mut req: libc::arpreq = unsafe { mem::zeroed() };
        let result = set_device(&mut req, "eth0");
        assert!(result.is_ok());

        // Verify device name was set
        let dev_name = std::str::from_utf8(
            // SAFETY: Converting c_char array to bytes for comparison
            unsafe { &*(&req.arp_dev[..4] as *const [libc::c_char] as *const [u8]) },
        )
        .unwrap();
        assert_eq!(dev_name, "eth0");
    }

    #[test]
    fn test_set_device_too_long() {
        // SAFETY: Initialize arpreq structure with zeros
        let mut req: libc::arpreq = unsafe { mem::zeroed() };
        let long_name = "a".repeat(libc::IFNAMSIZ);
        let result = set_device(&mut req, &long_name);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("device name too long")
        );
    }

    #[test]
    fn test_set_netmask_valid() {
        // SAFETY: Initialize arpreq structure with zeros
        let mut req: libc::arpreq = unsafe { mem::zeroed() };
        let mut flags = 0;
        let result = set_netmask(&mut req, "255.255.255.0", &mut flags);
        assert!(result.is_ok());
        assert_eq!(flags & libc::ATF_NETMASK, libc::ATF_NETMASK);

        // Verify netmask was set correctly
        // SAFETY: Reading the sockaddr_in we just set
        let mask_sa =
            unsafe { &*(&req.arp_netmask as *const libc::sockaddr as *const libc::sockaddr_in) };
        assert_eq!(mask_sa.sin_family, libc::AF_INET as libc::sa_family_t);
    }

    #[test]
    fn test_set_netmask_invalid() {
        // SAFETY: Initialize arpreq structure with zeros
        let mut req: libc::arpreq = unsafe { mem::zeroed() };
        let mut flags = 0;
        let result = set_netmask(&mut req, "invalid", &mut flags);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("invalid netmask"));
    }

    #[test]
    fn test_set_mac_from_string_valid() {
        // SAFETY: Initialize arpreq structure with zeros
        let mut req: libc::arpreq = unsafe { mem::zeroed() };
        let result = set_mac_from_string(&mut req, "aa:bb:cc:dd:ee:ff");
        assert!(result.is_ok());

        // Verify MAC was set correctly
        // SAFETY: Reading the sockaddr we just set
        let ha = unsafe { &*(&req.arp_ha as *const libc::sockaddr) };
        assert_eq!(ha.sa_family, libc::ARPHRD_ETHER as libc::sa_family_t);
        // SAFETY: Reading the MAC bytes we just set
        let mac_bytes = unsafe { std::slice::from_raw_parts(ha.sa_data.as_ptr() as *const u8, 6) };
        assert_eq!(mac_bytes, &[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    }

    #[test]
    fn test_set_mac_from_string_invalid() {
        // SAFETY: Initialize arpreq structure with zeros
        let mut req: libc::arpreq = unsafe { mem::zeroed() };
        let result = set_mac_from_string(&mut req, "invalid");
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("invalid hardware address")
        );
    }
}
