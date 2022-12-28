use std::io::{self};

use clap::Parser as _;
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

            // let (socket_receiver, mut socket_sender) = tokio::net::TcpStream::connect(destination)
            //     .await
            //     .wrap_err("couldn't connect to destination")?
            //     .into_split();
            // let mut socket_receiver =
            //     tokio::io::BufReader::with_capacity(MAX_PACKET_SIZE, socket_receiver);
            // let mut send_buffer = Vec::new();

            // let our_version = create_version_message(destination);
            // send_message(&mut send_buffer, &our_version, &mut socket_sender)
            //     .await
            //     .wrap_err("couldn't send version message")?;
            // info!(?our_version, "sent version message");

            // let mut buf = [0; 1000];
            // socket.read(&mut buf).wrap_err("couldn't read verack")?;
            // let (_, message) = Message::parse(&buf[..]).unwrap();
            // println!("{message:?}");
            Ok(())
        }
    }
}
