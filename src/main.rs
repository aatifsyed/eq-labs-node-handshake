use std::io::{Read, Write};

use clap::Parser;
use color_eyre::eyre::Context;
use eq_labs_node_handshake::{
    constants::Magic, Deparse, Message, MessageBody, NetworkAddressWithoutTime, Parse, Version,
    VersionFields106, VersionFields70001, VersionFieldsMandatory,
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

            let message = Message {
                magic: Magic::Main as _,
                body: MessageBody::Version(Version::Supports70001 {
                    version: 70001.try_into().unwrap(),
                    fields: VersionFieldsMandatory {
                        services: Default::default(),
                        timestamp: Default::default(),
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
                            ipv6: std::net::Ipv4Addr::UNSPECIFIED.to_ipv6_mapped(),
                            port: Default::default(),
                        },
                        nonce: 07_777_777_777_777_777_777u64,
                        user_agent: String::from("user-agent"),
                        start_height: 0,
                    },
                    fields_70001: VersionFields70001 { relay: false },
                }),
            };

            let mut buf = vec![0u8; message.deparsed_len()];
            message.deparse(&mut buf);

            socket.write_all(&buf).wrap_err("couldn't send version")?;

            let mut buf = [0; 1000];
            socket.read(&mut buf).wrap_err("couldn't read verack")?;
            let (_, message) = Message::parse(&buf[..]).unwrap();
            println!("{message:?}");
            Ok(())
        }
    }
}
