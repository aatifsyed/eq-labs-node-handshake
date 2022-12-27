use std::io::{self};

use clap::Parser as _;
use color_eyre::eyre::Context;
use eq_labs_node_handshake::{
    constants::Magic, Deparse as _, Message, MessageBody, Parse as _, ServicesAndNetworkAddress,
    Version, VersionFields106, VersionFields70001, VersionFieldsMandatory,
};
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _};
use tracing::{debug, info};

#[derive(Debug, clap::Parser)]
struct Cli {
    #[clap(subcommand)]
    subcommand: Subcommand,
}

#[derive(Debug, clap::Subcommand)]
enum Subcommand {
    DoHandshake { destination: std::net::SocketAddr },
}

const MAX_PACKET_SIZE: usize = 1024;

#[tokio::main]
async fn main() -> color_eyre::Result<()> {
    color_eyre::install()?;
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive(tracing_subscriber::filter::LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .with_writer(io::stderr)
        .init();

    let cli = Cli::parse();
    debug!(?cli);

    match cli.subcommand {
        Subcommand::DoHandshake { destination } => {
            info!(%destination, "performing handshake");

            let (socket_receiver, mut socket_sender) = tokio::net::TcpStream::connect(destination)
                .await
                .wrap_err("couldn't connect to destination")?
                .into_split();
            let mut socket_receiver =
                tokio::io::BufReader::with_capacity(MAX_PACKET_SIZE, socket_receiver);
            let mut send_buffer = Vec::new();

            let our_version = create_version_message(destination);
            send_message(&mut send_buffer, &our_version, &mut socket_sender)
                .await
                .wrap_err("couldn't send version message")?;
            info!(?our_version, "sent version message");

            // let mut buf = [0; 1000];
            // socket.read(&mut buf).wrap_err("couldn't read verack")?;
            // let (_, message) = Message::parse(&buf[..]).unwrap();
            // println!("{message:?}");
            Ok(())
        }
    }
}

async fn send_message(
    // Reuse this allocation
    send_buffer: &mut Vec<u8>,
    message: &Message,
    destination: &mut (impl tokio::io::AsyncWrite + Unpin),
) -> Result<(), io::Error> {
    send_buffer.resize(message.deparsed_len(), 0);
    message.deparse(send_buffer);
    destination.write_all(send_buffer).await
}

fn create_version_message(destination: std::net::SocketAddr) -> Message {
    Message {
        magic: Magic::Main as _,
        body: MessageBody::Version(Version::Supports70001 {
            version: 70001.try_into().unwrap(),
            fields: VersionFieldsMandatory {
                services: Default::default(),
                timestamp: chrono::Utc::now().naive_utc(),
                receiver: ServicesAndNetworkAddress {
                    services: Default::default(),
                    ipv6: match destination.ip() {
                        std::net::IpAddr::V4(v4) => v4.to_ipv6_mapped(),
                        std::net::IpAddr::V6(v6) => v6,
                    },
                    port: destination.port(),
                },
            },
            fields_106: VersionFields106 {
                sender: ServicesAndNetworkAddress {
                    services: Default::default(),
                    ipv6: std::net::Ipv4Addr::UNSPECIFIED.to_ipv6_mapped(),
                    port: 0,
                },
                nonce: 7_777_777_777_777_777_777u64,
                user_agent: String::from("user-agent"),
                start_height: 0,
            },
            fields_70001: VersionFields70001 { relay: false },
        }),
    }
}
