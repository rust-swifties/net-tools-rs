//! Rust implementation of the arp command from net-tools

mod arpreq;
mod hwtype;

use crate::{NetToolsError, RELEASE, Result};
use clap::Parser;
use dns_lookup::lookup_addr;
use hwtype::{hwtype_num_to_name, hwtype_to_num};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::mem;
use std::net::{IpAddr, Ipv4Addr, ToSocketAddrs};

#[derive(Parser, Debug)]
#[command(
    name = "arp",
    version = RELEASE,
    about = "Manipulate the system ARP cache",
    long_about = "Rust implementation of the arp command.\n\n\
                  Arp manipulates or displays the kernel's IPv4 network neighbour cache. \
                  It can add entries to the table, delete one or display the current content.\n\n\
                  ARP stands for Address Resolution Protocol, which is used to find the media \
                  access control address of a network neighbour for a given IPv4 Address."
)]
struct Args {
    /// Display (all) hosts in alternative (BSD) style
    #[arg(short = 'a', long = "all")]
    all: bool,

    /// Display (all) hosts in default (Linux) style
    #[arg(short = 'e')]
    linux_style: bool,

    /// Delete a specified entry (not yet supported)
    #[arg(short = 'd', long = "delete", conflicts_with_all = ["set", "file"])]
    delete: bool,

    /// Set a new ARP entry (not yet supported)
    #[arg(short = 's', long = "set", conflicts_with_all = ["delete", "file"])]
    set: bool,

    /// Read new entries from file or from /etc/ethers (not yet supported)
    #[arg(short = 'f', long = "file", conflicts_with_all = ["delete", "set"])]
    file: bool,

    /// Don't resolve names (show numerical addresses)
    #[arg(short = 'n', long = "numeric")]
    numeric: bool,

    /// Be verbose
    #[arg(short = 'v', long = "verbose")]
    verbose: bool,

    /// Specify network interface (e.g. eth0)
    #[arg(short = 'i', long = "device", value_name = "IF")]
    device: Option<String>,

    #[arg(
        short = 'D',
        long = "use-device",
        help = "Read <hwaddr> from given device"
    )]
    use_device: bool,

    /// Specify protocol family
    #[arg(
        short = 'A',
        short_alias = 'p',
        long = "protocol",
        value_name = "FAMILY"
    )]
    protocol: Option<String>,

    /// Specify hardware address type (default: ether)
    /// Possible values: ether, arcnet, pronet, ax25, netrom, etc.
    #[arg(short = 'H', short_alias = 't', long = "hw-type", value_name = "TYPE")]
    hw_type: Option<String>,

    /// Use symbolic names (not yet supported)
    #[arg(short = 'N', long = "symbolic", hide = true)]
    symbolic: bool,

    #[arg(
        trailing_var_arg = true,
        allow_hyphen_values = false,
        help = "Optional hostname or filename, followed by additional arguments\n\
                For display: [hostname]\n\
                For delete: <host> [pub|priv] [temp] [netmask <nm>] [dev <if>]\n\
                For set: <host> <hwaddr> [temp|pub|priv] [netmask <nm>] [dev <if>]\n\
                For file: [filename] (defaults to /etc/ethers)"
    )]
    args: Vec<String>,
}

pub fn main() {
    let args = Args::parse();
    let result = if args.delete {
        arp_del(&args)
    } else if args.set {
        arp_set(&args)
    } else if args.file {
        arp_file(&args)
    } else {
        arp_show(&args)
    };

    if let Err(e) = result {
        eprintln!("{}", e);
        // Match original C implementation's -1 exit code
        std::process::exit(255);
    }
}

/// ARP entry parsed from /proc/net/arp
#[derive(Debug, Clone)]
struct ArpEntry {
    ip: String,
    hw_type: u16,       // Hardware type (libc::ARPHRD_*)
    flags: libc::c_int, // ARP flags (libc::ATF_*)
    mac: String,
    mask: String,
    device: String,
}

/// Display the ARP cache
fn arp_show(args: &Args) -> Result<()> {
    let hostname_filter = if !args.args.is_empty() {
        Some(args.args[0].as_str())
    } else {
        None
    };

    let entries = read_arp_cache()?;

    let (ip_filter, original_hostname) = if let Some(host) = hostname_filter {
        let resolved_ip = resolve_or_passthrough(host, args.verbose)?;
        (Some(resolved_ip), Some(host.to_string()))
    } else {
        (None, None)
    };

    let filtered = filter_entries(
        entries.clone(),
        ip_filter.as_deref(),
        args.device.as_deref(),
        args.hw_type.as_deref(),
        args.verbose,
    )?;

    let showed = if args.all {
        display_bsd_style(&filtered, args.numeric)?
    } else {
        display_linux_style(&filtered, args.numeric)?
    };

    if args.verbose {
        println!(
            "Entries: {}\tSkipped: {}\tFound: {}",
            entries.len(),
            entries.len() - showed,
            showed
        );
    };

    if showed == 0 {
        if let (Some(host), Some(ip)) = (original_hostname, ip_filter) {
            if !args.all {
                println!("{} ({}) -- no entry", host, ip);
            }
        } else if args.device.is_some() || args.hw_type.is_some() {
            println!("arp: in {} entries no match found.", entries.len());
        }
    }

    Ok(())
}

/// Read and parse /proc/net/arp
fn read_arp_cache() -> Result<Vec<ArpEntry>> {
    let file = File::open("/proc/net/arp").map_err(NetToolsError::Io)?;
    let reader = BufReader::new(file);
    let mut entries = Vec::new();

    for (line_num, line) in reader.lines().enumerate() {
        let line = line.map_err(NetToolsError::Io)?;

        // Skip header line
        if line_num == 0 {
            continue;
        }

        if let Some(entry) = parse_arp_line(&line)? {
            entries.push(entry);
        }
    }

    Ok(entries)
}

/// Parse a single line from /proc/net/arp
/// Format: IP HW_type Flags HW_address Mask Device
fn parse_arp_line(line: &str) -> Result<Option<ArpEntry>> {
    let parts: Vec<&str> = line.split_whitespace().collect();

    if parts.len() < 6 {
        return Ok(None);
    }

    let hw_type = parse_hex_u16(parts[1])?;
    let flags = parse_hex_i32(parts[2])?;

    Ok(Some(ArpEntry {
        ip: parts[0].to_string(),
        hw_type,
        flags,
        mac: parts[3].to_string(),
        mask: parts[4].to_string(),
        device: parts[5].to_string(),
    }))
}

fn parse_hex_u16(s: &str) -> Result<u16> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    u16::from_str_radix(s, 16)
        .map_err(|_| NetToolsError::Other(format!("Invalid hex value: {}", s)))
}

fn parse_hex_i32(s: &str) -> Result<libc::c_int> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    i32::from_str_radix(s, 16)
        .map_err(|_| NetToolsError::Other(format!("Invalid hex value: {}", s)))
}

/// Filter ARP entries based on criteria
fn filter_entries(
    entries: Vec<ArpEntry>,
    hostname: Option<&str>,
    device: Option<&str>,
    hw_type: Option<&str>,
    verbose: bool,
) -> Result<Vec<ArpEntry>> {
    let mut filtered = Vec::new();

    let ip_filter = if let Some(host) = hostname {
        Some(resolve_or_passthrough(host, verbose)?)
    } else {
        None
    };

    let hw_type_num = if let Some(hwt) = hw_type {
        Some(hwtype_to_num(hwt)?)
    } else {
        None
    };

    for entry in entries {
        if let Some(ref ip) = ip_filter
            && &entry.ip != ip
        {
            continue;
        }

        if let Some(dev) = device
            && entry.device != dev
        {
            continue;
        }

        if let Some(hwt) = hw_type_num
            && entry.hw_type != hwt
        {
            continue;
        }

        filtered.push(entry);
    }

    Ok(filtered)
}

/// Display entries in Linux style (default table format)
fn display_linux_style(entries: &[ArpEntry], numeric: bool) -> Result<usize> {
    if entries.is_empty() {
        return Ok(0);
    }

    // Header with hardcoded spacing to match original implementation
    println!("Address                  HWtype  HWaddress           Flags Mask            Iface");

    for entry in entries {
        // Resolve hostname, then use IP if it's "?" (Match C implementation)
        let resolved_hostname = if numeric {
            "?".to_string()
        } else {
            match reverse_lookup(&entry.ip) {
                Some(name) if name != entry.ip => name,
                _ => "?".to_string(),
            }
        };

        let hostname = if resolved_hostname == "?" {
            &entry.ip
        } else {
            &resolved_hostname
        };

        // Truncate hostname to 23 characters max to match original C implementation
        let truncated_hostname = if hostname.len() > 23 {
            &hostname[..23]
        } else {
            hostname
        };

        let hw_name = hwtype_num_to_name(entry.hw_type);
        let flags_str = format_flags(entry.flags);
        let mask = if entry.mask == "*" { "" } else { &entry.mask };

        // Data format matches original C implementation:
        // printf("%-23.23s  ", name);                      // 23 chars + 2 spaces
        // printf("%-8.8s%-20.20s", xhw->name, hwa);        // 8 + 20 chars, no space between
        // printf("%-6.6s%-15.15s %s\n", flags, mask, dev); // 6 + 15 chars, 1 space before device
        if (entry.flags & libc::ATF_COM) == 0 {
            if (entry.flags & libc::ATF_PUBL) != 0 {
                println!(
                    "{:<23}  {:<8}{:<20}{:<6}{:<15} {}",
                    truncated_hostname, "*", "<from_interface>", flags_str, mask, entry.device
                );
            } else {
                println!(
                    "{:<23}  {:<8}{:<20}{:<6}{:<15} {}",
                    truncated_hostname, "", "(incomplete)", flags_str, mask, entry.device
                );
            }
        } else {
            println!(
                "{:<23}  {:<8}{:<20}{:<6}{:<15} {}",
                truncated_hostname, hw_name, entry.mac, flags_str, mask, entry.device
            );
        }
    }

    Ok(entries.len())
}

/// Display entries in BSD style (-a flag)
fn display_bsd_style(entries: &[ArpEntry], numeric: bool) -> Result<usize> {
    for entry in entries {
        // Show "?" when reverse lookup fails or in numeric mode
        let hostname = if numeric {
            "?".to_string()
        } else {
            match reverse_lookup(&entry.ip) {
                Some(name) if name != entry.ip => name,
                _ => "?".to_string(),
            }
        };

        let hw_name = hwtype_num_to_name(entry.hw_type);

        print!("{} ({}) at ", hostname, entry.ip);

        if (entry.flags & libc::ATF_COM) == 0 {
            if (entry.flags & libc::ATF_PUBL) != 0 {
                print!("<from_interface> ");
            } else {
                print!("<incomplete> ");
            }
        } else {
            print!("{} [{}] ", entry.mac, hw_name);
        }

        if (entry.flags & libc::ATF_NETMASK) != 0 && entry.mask != "*" {
            print!("netmask {} ", entry.mask);
        }
        if (entry.flags & libc::ATF_PERM) != 0 {
            print!("PERM ");
        }
        if (entry.flags & libc::ATF_PUBL) != 0 {
            print!("PUB ");
        }
        if (entry.flags & libc::ATF_USETRAILERS) != 0 {
            print!("TRAIL ");
        }
        if (entry.flags & libc::ATF_DONTPUB) != 0 {
            print!("DONTPUB ");
        }

        println!("on {}", entry.device);
    }

    Ok(entries.len())
}

/// Format ARP flags as string (C=complete, M=permanent, P=published, T=trailers, !=dontpub)
fn format_flags(flags: libc::c_int) -> String {
    let mut s = String::new();
    if (flags & libc::ATF_COM) != 0 {
        s.push('C');
    }
    if (flags & libc::ATF_PERM) != 0 {
        s.push('M');
    }
    if (flags & libc::ATF_PUBL) != 0 {
        s.push('P');
    }
    if (flags & libc::ATF_USETRAILERS) != 0 {
        s.push('T');
    }
    if (flags & libc::ATF_DONTPUB) != 0 {
        s.push('!');
    }
    s
}

fn resolve_or_passthrough(host: &str, verbose: bool) -> Result<String> {
    if host.parse::<IpAddr>().is_ok() {
        return Ok(host.to_string());
    }

    if verbose {
        eprintln!("Resolving '{}'...", host);
    }

    let addr = format!("{}:0", host)
        .to_socket_addrs()
        .map_err(|_| NetToolsError::Other(format!("{}: Unknown host", host)))?
        .next()
        .ok_or_else(|| NetToolsError::Other(format!("{}: Unknown host", host)))?;

    Ok(addr.ip().to_string())
}

/// Reverse DNS lookup
fn reverse_lookup(ip: &str) -> Option<String> {
    let addr: IpAddr = ip.parse().ok()?;
    lookup_addr(&addr).ok()
}

/// Delete an ARP entry
fn arp_del(args: &Args) -> Result<()> {
    if args.args.is_empty() {
        return Err(NetToolsError::Other("arp: need host name".to_string()));
    }

    let host = &args.args[0];
    let mut flags = 0;
    let mut device: Option<String> = args.device.clone();
    let mut netmask: Option<String> = None;

    // Parse additional arguments
    let mut i = 1;
    while i < args.args.len() {
        match args.args[i].as_str() {
            "pub" => flags |= libc::ATF_PUBL,
            "priv" => flags &= !libc::ATF_PUBL,
            "temp" => flags &= !libc::ATF_PERM,
            "netmask" => {
                i += 1;
                if i >= args.args.len() {
                    return Err(NetToolsError::Other("arp: need netmask value".to_string()));
                }
                netmask = Some(args.args[i].clone());
            }
            "dev" => {
                i += 1;
                if i >= args.args.len() {
                    return Err(NetToolsError::Other("arp: need device name".to_string()));
                }
                device = Some(args.args[i].clone());
            }
            _ => {
                return Err(NetToolsError::Other(format!(
                    "arp: invalid argument: {}",
                    args.args[i]
                )));
            }
        }
        i += 1;
    }

    let ip = resolve_or_passthrough(host, args.verbose)?;

    // SAFETY: Creating a socket with valid domain, type, and protocol
    let sockfd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if sockfd < 0 {
        return Err(NetToolsError::Io(std::io::Error::last_os_error()));
    }

    // SAFETY: Initialize arpreq structure with zeros
    let mut req: libc::arpreq = unsafe { mem::zeroed() };

    let ip_addr: Ipv4Addr = ip
        .parse()
        .map_err(|_| NetToolsError::Other(format!("arp: invalid IP address: {}", ip)))?;

    // SAFETY: Casting to sockaddr_in to set IP address
    let sa = unsafe { &mut *(&mut req.arp_pa as *mut libc::sockaddr as *mut libc::sockaddr_in) };
    sa.sin_family = libc::AF_INET as libc::sa_family_t;
    sa.sin_addr.s_addr = u32::from(ip_addr).to_be();

    if let Some(ref dev) = device {
        let dev_bytes = dev.as_bytes();
        if dev_bytes.len() >= libc::IFNAMSIZ {
            // SAFETY: Closing the socket before returning error
            unsafe {
                libc::close(sockfd);
            }
            return Err(NetToolsError::Other(format!(
                "arp: device name too long: {}",
                dev
            )));
        }
        // SAFETY: Casting byte slice to c_char slice for copy
        // Both types are single-byte and the length is preserved
        req.arp_dev[..dev_bytes.len()]
            .copy_from_slice(unsafe { &*(dev_bytes as *const [u8] as *const [libc::c_char]) });
    }

    if let Some(ref mask) = netmask {
        let mask_addr: Ipv4Addr = mask.parse().map_err(|_| {
            // SAFETY: Closing the socket before returning error
            unsafe {
                libc::close(sockfd);
            }
            NetToolsError::Other(format!("arp: invalid netmask: {}", mask))
        })?;

        // SAFETY: Casting to sockaddr_in to set netmask
        let mask_sa = unsafe {
            &mut *(&mut req.arp_netmask as *mut libc::sockaddr as *mut libc::sockaddr_in)
        };
        mask_sa.sin_family = libc::AF_INET as libc::sa_family_t;
        mask_sa.sin_addr.s_addr = u32::from(mask_addr).to_be();
        flags |= libc::ATF_NETMASK;
    }

    req.arp_flags = flags;

    // Perform the delete operation
    // SAFETY: Calling ioctl with valid socket fd and properly initialized arpreq structure
    let result = unsafe { libc::ioctl(sockfd, libc::SIOCDARP as _, &req) };

    // SAFETY: Close the socket
    unsafe {
        libc::close(sockfd);
    }

    if result < 0 {
        let err = std::io::Error::last_os_error();
        match err.raw_os_error() {
            Some(libc::ENXIO) | Some(libc::ENOENT) => {
                eprintln!("No ARP entry for {}", host);
                std::process::exit(255);
            }
            _ => {
                return Err(NetToolsError::Other(format!("SIOCDARP: {}", err)));
            }
        }
    }

    Ok(())
}

/// Set/add an ARP entry
fn arp_set(args: &Args) -> Result<()> {
    let mut options = arpreq::parse_set_args(&args.args, args.use_device, args.device.clone())?;

    let ip = resolve_or_passthrough(&options.host, args.verbose)?;

    // SAFETY: Creating a socket with valid domain, type, and protocol
    let sockfd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if sockfd < 0 {
        return Err(NetToolsError::Io(std::io::Error::last_os_error()));
    }

    // SAFETY: Initialize arpreq structure with zeros
    let mut req: libc::arpreq = unsafe { mem::zeroed() };

    arpreq::set_ip(&mut req, &ip).inspect_err(|_e| {
        // SAFETY: Closing valid socket fd before error return
        unsafe {
            libc::close(sockfd);
        }
    })?;

    // Set MAC address (from device or string)
    if options.use_device {
        if let Some(ref dev) = options.device {
            arpreq::set_mac_from_device(sockfd, &mut req, dev).inspect_err(|_e| {
                // SAFETY: Closing valid socket fd before error return
                unsafe {
                    libc::close(sockfd);
                }
            })?;
        }
    } else {
        arpreq::set_mac_from_string(&mut req, &options.mac).inspect_err(|_e| {
            // SAFETY: Closing valid socket fd before error return
            unsafe {
                libc::close(sockfd);
            }
        })?;
    }

    // Set device name if specified
    if let Some(ref dev) = options.device {
        arpreq::set_device(&mut req, dev).inspect_err(|_e| {
            // SAFETY: Closing valid socket fd before error return
            unsafe {
                libc::close(sockfd);
            }
        })?;
    }

    // Set netmask if specified
    if let Some(ref mask) = options.netmask {
        arpreq::set_netmask(&mut req, mask, &mut options.flags).inspect_err(|_e| {
            // SAFETY: Closing valid socket fd before error return
            unsafe {
                libc::close(sockfd);
            }
        })?;
    }

    req.arp_flags = options.flags;

    if args.verbose {
        eprintln!("arp: SIOCSARP()");
    }

    // SAFETY: Calling ioctl with valid socket fd and properly initialized arpreq structure
    let result = unsafe { libc::ioctl(sockfd, libc::SIOCSARP as _, &req) };

    // SAFETY: Close the socket
    unsafe {
        libc::close(sockfd);
    }

    if result < 0 {
        let err = std::io::Error::last_os_error();
        let err_msg = match err.raw_os_error() {
            Some(libc::ENODEV) => "No such device",
            Some(libc::EPERM) => "Operation not permitted",
            Some(libc::EACCES) => "Permission denied",
            Some(libc::ENXIO) => "No such device or address",
            _ => return Err(NetToolsError::Io(err)),
        };
        return Err(NetToolsError::Other(format!("SIOCSARP: {}", err_msg)));
    }

    Ok(())
}

fn arp_file(_args: &Args) -> Result<()> {
    Err(NetToolsError::Other(
        "arp -f not yet implemented".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_hex_u16() {
        assert_eq!(parse_hex_u16("0x1").unwrap(), 1);
        assert_eq!(parse_hex_u16("0x10").unwrap(), 16);
        assert_eq!(parse_hex_u16("0xff").unwrap(), 255);
        assert_eq!(parse_hex_u16("0xFFFF").unwrap(), 65535);
        assert_eq!(parse_hex_u16("1").unwrap(), 1);
        assert_eq!(parse_hex_u16("ff").unwrap(), 255);
        assert!(parse_hex_u16("invalid").is_err());
        assert!(parse_hex_u16("0xGGGG").is_err());
    }

    #[test]
    fn test_parse_hex_i32() {
        assert_eq!(parse_hex_i32("0x0").unwrap(), 0);
        assert_eq!(parse_hex_i32("0x2").unwrap(), 2);
        assert_eq!(parse_hex_i32("0x6").unwrap(), 6);
        assert_eq!(parse_hex_i32("0xc").unwrap(), 12);
        assert_eq!(parse_hex_i32("2").unwrap(), 2);
        assert!(parse_hex_i32("invalid").is_err());
    }

    #[test]
    fn test_parse_arp_line() {
        let line = "192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0";
        let entry = parse_arp_line(line).unwrap().unwrap();
        assert_eq!(entry.ip, "192.168.1.1");
        assert_eq!(entry.hw_type, 1);
        assert_eq!(entry.flags, 2);
        assert_eq!(entry.mac, "aa:bb:cc:dd:ee:ff");
        assert_eq!(entry.mask, "*");
        assert_eq!(entry.device, "eth0");
    }

    #[test]
    fn test_parse_arp_line_with_mask() {
        let line =
            "10.0.0.1         0x1         0x6         11:22:33:44:55:66     255.255.255.0    wlan0";
        let entry = parse_arp_line(line).unwrap().unwrap();
        assert_eq!(entry.ip, "10.0.0.1");
        assert_eq!(entry.hw_type, 1);
        assert_eq!(entry.flags, 6);
        assert_eq!(entry.mac, "11:22:33:44:55:66");
        assert_eq!(entry.mask, "255.255.255.0");
        assert_eq!(entry.device, "wlan0");
    }

    #[test]
    fn test_parse_arp_line_incomplete() {
        let line = "192.168.1.2      0x1         0x0         00:00:00:00:00:00     *        eth0";
        let entry = parse_arp_line(line).unwrap().unwrap();
        assert_eq!(entry.flags, 0);
        assert_eq!(entry.mac, "00:00:00:00:00:00");
    }

    #[test]
    fn test_parse_arp_line_invalid() {
        let line = "invalid line";
        assert!(parse_arp_line(line).unwrap().is_none());
    }

    #[test]
    fn test_format_flags() {
        assert_eq!(format_flags(0), "");
        assert_eq!(format_flags(libc::ATF_COM), "C");
        assert_eq!(format_flags(libc::ATF_PERM), "M");
        assert_eq!(format_flags(libc::ATF_PUBL), "P");
        assert_eq!(format_flags(libc::ATF_COM | libc::ATF_PERM), "CM");
        assert_eq!(format_flags(libc::ATF_COM | libc::ATF_PUBL), "CP");
        assert_eq!(
            format_flags(libc::ATF_COM | libc::ATF_PERM | libc::ATF_PUBL),
            "CMP"
        );
    }

    #[test]
    fn test_resolve_or_passthrough_ip() {
        let result = resolve_or_passthrough("192.168.1.1", false).unwrap();
        assert_eq!(result, "192.168.1.1");

        let result = resolve_or_passthrough("10.0.0.1", false).unwrap();
        assert_eq!(result, "10.0.0.1");
    }

    #[test]
    fn test_resolve_or_passthrough_localhost() {
        let result = resolve_or_passthrough("localhost", false);
        assert!(result.is_ok());
        let ip = result.unwrap();
        assert!(ip == "127.0.0.1" || ip == "::1");
    }

    #[test]
    fn test_resolve_or_passthrough_invalid() {
        let result = resolve_or_passthrough("invalid.hostname.that.does.not.exist.12345", false);
        assert!(result.is_err());
    }

    #[test]
    fn test_filter_entries_by_ip() {
        let entries = vec![
            ArpEntry {
                ip: "192.168.1.1".to_string(),
                hw_type: 1,
                flags: 2,
                mac: "aa:bb:cc:dd:ee:ff".to_string(),
                mask: "*".to_string(),
                device: "eth0".to_string(),
            },
            ArpEntry {
                ip: "192.168.1.2".to_string(),
                hw_type: 1,
                flags: 2,
                mac: "11:22:33:44:55:66".to_string(),
                mask: "*".to_string(),
                device: "eth0".to_string(),
            },
        ];

        let filtered = filter_entries(entries, Some("192.168.1.1"), None, None, false).unwrap();
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].ip, "192.168.1.1");
    }

    #[test]
    fn test_filter_entries_by_device() {
        let entries = vec![
            ArpEntry {
                ip: "192.168.1.1".to_string(),
                hw_type: 1,
                flags: 2,
                mac: "aa:bb:cc:dd:ee:ff".to_string(),
                mask: "*".to_string(),
                device: "eth0".to_string(),
            },
            ArpEntry {
                ip: "192.168.1.2".to_string(),
                hw_type: 1,
                flags: 2,
                mac: "11:22:33:44:55:66".to_string(),
                mask: "*".to_string(),
                device: "wlan0".to_string(),
            },
        ];

        let filtered = filter_entries(entries, None, Some("eth0"), None, false).unwrap();
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].device, "eth0");
    }

    #[test]
    fn test_filter_entries_by_hw_type() {
        let entries = vec![
            ArpEntry {
                ip: "192.168.1.1".to_string(),
                hw_type: libc::ARPHRD_ETHER,
                flags: 2,
                mac: "aa:bb:cc:dd:ee:ff".to_string(),
                mask: "*".to_string(),
                device: "eth0".to_string(),
            },
            ArpEntry {
                ip: "192.168.1.2".to_string(),
                hw_type: libc::ARPHRD_LOOPBACK,
                flags: 2,
                mac: "00:00:00:00:00:00".to_string(),
                mask: "*".to_string(),
                device: "lo".to_string(),
            },
        ];

        let filtered = filter_entries(entries, None, None, Some("ether"), false).unwrap();
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].hw_type, libc::ARPHRD_ETHER);
    }

    #[test]
    fn test_filter_entries_multiple_criteria() {
        let entries = vec![
            ArpEntry {
                ip: "192.168.1.1".to_string(),
                hw_type: libc::ARPHRD_ETHER,
                flags: 2,
                mac: "aa:bb:cc:dd:ee:ff".to_string(),
                mask: "*".to_string(),
                device: "eth0".to_string(),
            },
            ArpEntry {
                ip: "192.168.1.2".to_string(),
                hw_type: libc::ARPHRD_ETHER,
                flags: 2,
                mac: "11:22:33:44:55:66".to_string(),
                mask: "*".to_string(),
                device: "wlan0".to_string(),
            },
        ];

        let filtered = filter_entries(
            entries,
            Some("192.168.1.1"),
            Some("eth0"),
            Some("ether"),
            false,
        )
        .unwrap();
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].ip, "192.168.1.1");
        assert_eq!(filtered[0].device, "eth0");
    }

    #[test]
    fn test_filter_entries_no_match() {
        let entries = vec![ArpEntry {
            ip: "192.168.1.1".to_string(),
            hw_type: 1,
            flags: 2,
            mac: "aa:bb:cc:dd:ee:ff".to_string(),
            mask: "*".to_string(),
            device: "eth0".to_string(),
        }];

        let filtered = filter_entries(entries, Some("192.168.1.2"), None, None, false).unwrap();
        assert_eq!(filtered.len(), 0);
    }

    #[test]
    fn test_reverse_lookup_localhost() {
        let result = reverse_lookup("127.0.0.1");
        assert!(result.is_some());
        let hostname = result.unwrap();
        assert!(hostname.contains("localhost") || hostname.contains("127.0.0.1"));
    }

    #[test]
    fn test_reverse_lookup_invalid_ip() {
        let result = reverse_lookup("invalid");
        assert!(result.is_none());
    }
}
