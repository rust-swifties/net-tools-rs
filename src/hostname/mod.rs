//! Rust implementation of the hostname command from net-tools

use crate::{NetToolsError, RELEASE, Result};
use clap::Parser;
use nix::ifaddrs::getifaddrs;
use nix::sys::socket::SockaddrLike;
use nix::unistd;
use std::fs;
use std::net::{IpAddr, ToSocketAddrs};

#[derive(Parser, Debug)]
#[command(
    name = "hostname",
    version = RELEASE,
    about = "Show or set system host name",
    long_about = "Rust implementation of the hostname command.\n\n\
                  This command can get or set the host name or the NIS domain name. You can\n\
                  also get the DNS domain or the FQDN (fully qualified domain name).\n\
                  Unless you are using bind or NIS for host lookups you can change the\n\
                  FQDN (Fully Qualified Domain Name) and the DNS domain name (which is\n\
                  part of the FQDN) in the /etc/hosts file."
)]
struct Args {
    /// new hostname to set
    hostname: Option<String>,

    /// DNS domain name
    #[arg(short, long)]
    domain: bool,

    /// read host name or NIS domain name from given file
    #[arg(short = 'F', long = "file")]
    file: Option<String>,

    /// addresses for the host name
    #[arg(short = 'i', long = "ip-address")]
    ip_address: bool,

    /// all addresses for the host
    #[arg(short = 'I', long = "all-ip-addresses")]
    all_ip_addresses: bool,

    /// short host name
    #[arg(short, long)]
    short: bool,

    /// NIS/YP domain name
    #[arg(short = 'y', long = "yp", visible_alias = "nis")]
    yp: bool,

    /// verbose output
    #[arg(short, long)]
    verbose: bool,
}

pub fn main() {
    let args = Args::parse();

    let result = if args.yp {
        handle_domainname(&args)
    } else if args.domain {
        handle_dns_domain(&args)
    } else {
        handle_hostname(&args)
    };

    if let Err(e) = result {
        eprintln!("hostname: {}", e);
        std::process::exit(1);
    }
}

/// Handle hostname operations (get/set)
fn handle_hostname(args: &Args) -> Result<()> {
    if let Some(file) = &args.file {
        let name = read_name_from_file(file, args.verbose)?;
        return set_hostname(&name, args.verbose);
    }

    if let Some(name) = &args.hostname {
        return set_hostname(name, args.verbose);
    }

    let hostname = get_hostname()?;

    if args.verbose {
        eprintln!("gethostname()=`{hostname}'");
    }

    if args.short {
        let short = hostname.split('.').next().unwrap_or(&hostname);
        println!("{short}");
    } else if args.ip_address {
        show_ip_addresses(&hostname, args.verbose)?;
    } else if args.all_ip_addresses {
        show_all_ip_addresses()?;
    } else {
        println!("{hostname}");
    }

    Ok(())
}

/// Handle NIS domainname operations
fn handle_domainname(args: &Args) -> Result<()> {
    if let Some(file) = &args.file {
        let name = read_name_from_file(file, args.verbose)?;
        return set_domainname(&name, args.verbose);
    }

    if let Some(name) = &args.hostname {
        return set_domainname(name, args.verbose);
    }

    let domainname = get_domainname()?;

    if args.verbose {
        eprintln!("getdomainname()=`{}'", domainname);
    }

    println!("{}", domainname);
    Ok(())
}

/// Handle DNS domain name display
fn handle_dns_domain(args: &Args) -> Result<()> {
    if args.file.is_some() || args.hostname.is_some() {
        return Err(NetToolsError::Other(
            "You can't change the DNS domain name with this command\n\
             \nUnless you are using bind or NIS for host lookups you can change the DNS\n\
             domain name (which is part of the FQDN) in the /etc/hosts file."
                .to_string(),
        ));
    }

    let hostname = get_hostname()?;
    show_dns_domain(&hostname)?;

    Ok(())
}

/// Get the current host name
fn get_hostname() -> Result<String> {
    let name = unistd::gethostname()?;
    Ok(name.to_string_lossy().to_string())
}

/// Set the host name
fn set_hostname(name: &str, verbose: bool) -> Result<()> {
    if verbose {
        eprintln!("Setting hostname to `{name}'");
    }

    unistd::sethostname(name).map_err(|e| match e {
        nix::errno::Errno::EPERM => NetToolsError::PermissionDenied(
            "you don't have permission to set the host name".to_string(),
        ),
        nix::errno::Errno::EINVAL => NetToolsError::NameTooLong("hostname too long".to_string()),
        _ => NetToolsError::Nix(e),
    })?;

    Ok(())
}

/// Get the current NIS domain name
fn get_domainname() -> Result<String> {
    let mut buf = [0u8; 256];
    // SAFETY: getdomainname is passed a valid buffer with correct size
    let ret = unsafe { libc::getdomainname(buf.as_mut_ptr() as *mut i8, buf.len()) };
    if ret != 0 {
        return Err(NetToolsError::Nix(nix::errno::Errno::last()));
    }

    let len = buf.iter().position(|&x| x == 0).unwrap_or(buf.len());
    let name = std::str::from_utf8(&buf[..len])
        .map_err(|_| NetToolsError::Other("Invalid UTF-8 in domainname".to_string()))?;

    Ok(name.to_string())
}

/// Set the NIS domain name
fn set_domainname(name: &str, verbose: bool) -> Result<()> {
    if verbose {
        eprintln!("Setting domainname to `{name}'");
    }

    // SAFETY: setdomainname is passed a valid string pointer and length
    let ret = unsafe { libc::setdomainname(name.as_ptr() as *const i8, name.len()) };

    if ret != 0 {
        let errno = nix::errno::Errno::last();
        return Err(match errno {
            nix::errno::Errno::EPERM => NetToolsError::PermissionDenied(
                "you don't have permission to set the domain name".to_string(),
            ),
            nix::errno::Errno::EINVAL => {
                NetToolsError::NameTooLong("domainname too long".to_string())
            }
            _ => NetToolsError::Nix(errno),
        });
    }

    Ok(())
}

/// Read hostname/domainname from file
fn read_name_from_file(file: &str, verbose: bool) -> Result<String> {
    let contents =
        fs::read_to_string(file).map_err(|_| NetToolsError::Other(format!("can't open {file}")))?;

    for line in contents.lines() {
        let line = line.trim();

        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if verbose {
            eprintln!(">> {line}");
        }

        return Ok(line.to_string());
    }

    Err(NetToolsError::Other(format!(
        "No valid hostname found in `{file}`"
    )))
}

/// Show DNS domain name (part after first dot)
fn show_dns_domain(hostname: &str) -> Result<()> {
    if let Some(pos) = hostname.find('.') {
        println!("{}", &hostname[pos + 1..]);
    } else {
        println!();
    }
    Ok(())
}

/// Show IP addresses for hostname (DNS lookup)
fn show_ip_addresses(hostname: &str, verbose: bool) -> Result<()> {
    if verbose {
        eprintln!("Resolving `{}' ...", hostname);
    }

    let addrs = format!("{}:0", hostname)
        .to_socket_addrs()
        .map_err(|_| NetToolsError::Other(format!("Cannot resolve hostname: {}", hostname)))?;

    let ips: Vec<IpAddr> = addrs.map(|addr| addr.ip()).collect();

    if verbose {
        for ip in &ips {
            eprintln!("Result: h_addr_list=`{}'", ip);
        }
    }

    for (i, ip) in ips.iter().enumerate() {
        if i == 0 {
            print!("{}", ip);
        } else {
            print!(" {}", ip);
        }
    }
    println!();

    Ok(())
}

/// Show all IP addresses for all network interfaces (excluding loopback)
fn show_all_ip_addresses() -> Result<()> {
    let ifaddrs = getifaddrs()?;

    let mut ips = Vec::new();

    for ifaddr in ifaddrs {
        if let Some(address) = ifaddr.address {
            let ip = match address.family() {
                Some(nix::sys::socket::AddressFamily::Inet) => {
                    if let Some(sockaddr) = address.as_sockaddr_in() {
                        let ip = sockaddr.ip();
                        if !ip.is_loopback() {
                            Some(IpAddr::V4(ip))
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                }
                Some(nix::sys::socket::AddressFamily::Inet6) => {
                    if let Some(sockaddr) = address.as_sockaddr_in6() {
                        let ip = sockaddr.ip();
                        if !ip.is_loopback() && !is_link_local_ipv6(&ip) {
                            Some(IpAddr::V6(ip))
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                }
                _ => None,
            };

            if let Some(ip) = ip {
                ips.push(ip);
            }
        }
    }

    for (i, ip) in ips.iter().enumerate() {
        if i == 0 {
            print!("{}", ip);
        } else {
            print!(" {}", ip);
        }
    }
    println!();

    Ok(())
}

/// Check if an IPv6 address is link-local (fe80::/10)
fn is_link_local_ipv6(ip: &std::net::Ipv6Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 0xfe && (octets[1] & 0xc0) == 0x80
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_link_local_ipv6() {
        let link_local = "fe80::1".parse().unwrap();
        assert!(is_link_local_ipv6(&link_local));

        let link_local2 = "fe80:0000:0000:0000:0000:0000:0000:0001".parse().unwrap();
        assert!(is_link_local_ipv6(&link_local2));

        let global = "2001:db8::1".parse().unwrap();
        assert!(!is_link_local_ipv6(&global));

        let loopback = "::1".parse().unwrap();
        assert!(!is_link_local_ipv6(&loopback));
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_get_hostname() {
        let hostname = get_hostname().unwrap();
        assert!(!hostname.is_empty());
    }

    #[test]
    fn test_show_dns_domain() {
        let hostname = "host.example.com";
        let result = show_dns_domain(hostname);
        assert!(result.is_ok());

        let hostname = "localhost";
        let result = show_dns_domain(hostname);
        assert!(result.is_ok());
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_read_name_from_file_invalid() {
        let result = read_name_from_file("/tmp/nonexistent_file_12345", false);
        assert!(result.is_err());
    }

    #[test]
    fn test_getdomainname() {
        let result = get_domainname();

        match result {
            Ok(domain) => {
                assert!(domain.len() <= 256);

                if !domain.is_empty() && domain != "(none)" {
                    assert!(
                        domain
                            .chars()
                            .all(|c| c.is_alphanumeric() || c == '.' || c == '-' || c == '_')
                    );
                }
            }
            Err(e) => {
                eprintln!("getdomainname failed (expected on some systems): {}", e);
            }
        }
    }

    #[test]
    fn test_args_with_file() {
        let args = Args::try_parse_from(["hostname", "-F", "/etc/hostname"]).unwrap();
        assert_eq!(args.file.as_deref(), Some("/etc/hostname"));
    }

    #[test]
    fn test_args_with_hostname_to_set() {
        let args = Args::try_parse_from(["hostname", "newhostname"]).unwrap();
        assert_eq!(args.hostname.as_deref(), Some("newhostname"));
    }
}
