use std::io::{Read, Write};

use clap::Parser;
use color_eyre::eyre::Context;
use eq_labs_node_handshake::{
    constants::Magic, Deparse, Header, NetworkAddressWithoutTime, Version, VersionFields106,
    VersionFieldsMandatory,
};
use tracing::info;

#[derive(clap::Parser)]
struct Cli {
    #[clap(subcommand)]
    subcommand: Subcommand,
}

#[derive(clap::Subcommand)]
enum Subcommand {
    DoHandshake { destination: std::net::SocketAddr },
}

fn main() -> color_eyre::Result<()> {
    let cli = Cli::parse();
    match cli.subcommand {
        Subcommand::DoHandshake { destination } => {
            info!(?destination, "ping");
            let mut socket = std::net::TcpStream::connect(destination)
                .wrap_err("couldn't connect to destination")?;

            let body = Version::Supports106 {
                version: 70000.try_into().unwrap(),
                fields: VersionFieldsMandatory {
                    services: Default::default(),
                    timestamp: chrono::Utc::now().naive_utc(),
                    receiver: NetworkAddressWithoutTime {
                        services: Default::default(),
                        ipv6: match destination.ip() {
                            std::net::IpAddr::V4(v4) => v4.to_ipv6_mapped(),
                            std::net::IpAddr::V6(v6) => v6,
                        },
                        port: destination.port(),
                    },
                },
                fields_106: VersionFields106 {
                    sender: NetworkAddressWithoutTime {
                        services: Default::default(),
                        ipv6: std::net::Ipv6Addr::UNSPECIFIED,
                        port: Default::default(),
                    },
                    nonce: 42069,
                    user_agent: String::from("user-agent"),
                    start_height: 0,
                },
            };

            let mut buf = vec![0u8; std::mem::size_of::<Header>() + body.deparsed_len()];

            body.deparse(&mut buf[std::mem::size_of::<Header>()..]);
            let checksum = sha256::digest(&buf[std::mem::size_of::<Header>()..])
                .as_bytes()
                .chunks(4)
                .map(|c| [c[0], c[1], c[2], c[3]])
                .next()
                .unwrap();

            let header = Header {
                magic: Magic::Main as _,
                command: *b"version\0\0\0\0\0",
                length: body.deparsed_len().try_into().unwrap(),
                checksum,
            };

            header.deparse(&mut buf);

            socket.write_all(&buf).wrap_err("couldn't send version")?;

            let mut buf = [0; 24];
            socket.read(&mut buf).wrap_err("couldn't read verack")?;
            println!("{buf:x?}");
            Ok(())
        }
    }
}
