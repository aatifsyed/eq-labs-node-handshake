use std::io::{Read, Write};

use clap::Parser;
use color_eyre::eyre::Context;
use tracing::info;

#[derive(clap::Parser)]
struct Cli {
    #[clap(subcommand)]
    subcommand: Subcommand,
}

#[derive(clap::Subcommand)]
enum Subcommand {
    Ping { destination: std::net::SocketAddr },
}

fn main() -> color_eyre::Result<()> {
    let cli = Cli::parse();
    match cli.subcommand {
        Subcommand::Ping { destination } => {
            info!(?destination, "ping");
            let mut socket = std::net::TcpStream::connect(destination)
                .wrap_err("couldn't connect to destination")?;

            socket
                .write_all(&[
                    0xF9, 0xBE, 0xB4, 0xD9, // magic
                    0x70, 0x69, 0x6E, 0x67, // "ping"
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // pad to 12
                    0x00, 0x00, 0x00, 0x00, // no payload length
                    0x00, 0x00, 0x00, 0x00, // no payload checksum
                ])
                .wrap_err("couldn't send ping")?;

            let mut buf = [0; 24];
            socket.read(&mut buf).wrap_err("couldn't read pong")?;
            println!("{buf:x?}");
            Ok(())
        }
    }
}
