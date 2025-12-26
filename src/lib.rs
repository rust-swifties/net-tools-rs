pub mod arp;
pub mod error;
pub mod hostname;
pub mod nameif;

pub use arp::main as arp_main;
pub use error::{NetToolsError, Result};
pub use hostname::main as hostname_main;
pub use nameif::main as nameif_main;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const RELEASE: &str = concat!("net-tools-rs ", env!("CARGO_PKG_VERSION"));
