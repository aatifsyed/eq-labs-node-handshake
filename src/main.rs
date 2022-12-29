use std::{io, time};

use clap::Parser as _;
use color_eyre::eyre::{bail, eyre, Context, ContextCompat};
use eq_labs_node_handshake::{
    constants::Magic, wire, Codec, Decoder, Encoder, Message, MessageBody,
};
use futures::{SinkExt as _, StreamExt as _};
use tracing::{debug, info};
use zerocopy::FromBytes;

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

            let socket = tokio::net::TcpStream::connect(destination)
                .await
                .wrap_err("couldn't connect to destination")?;

            let mut transport = tokio_util::codec::Framed::new(
                socket,
                Codec::new(
                    Encoder {},
                    Decoder {
                        max_frame_length: None,
                    },
                ),
            );

            // https://en.bitcoin.it/wiki/Version_Handshake

            transport
                .send(Message {
                    network: Magic::Main as _,
                    body: MessageBody::Version(wire::Version::Supports106(wire::Version106 {
                        fields_mandatory: wire::VersionFieldsMandatory {
                            version: 70000.into(),
                            services: 0.into(),
                            timestamp: current_unix_secs().into(),
                            receiver: wire::NetworkAddressWithoutTime::new(
                                0,
                                destination.ip(),
                                destination.port(),
                            ),
                        },
                        fields_106: wire::VersionFields106 {
                            sender: wire::NetworkAddressWithoutTime::new_zeroed(),
                            nonce: 0.into(),
                            user_agent: wire::VarStr::borrowed("me!"),
                            start_height: 0.into(),
                        },
                    })),
                })
                .await
                .wrap_err("couldn't send version advertisement")?;

            info!("sent advertisement");

            let message = transport
                .next()
                .await
                .wrap_err("transport closed before version advertisement received")?
                .wrap_err("peer sent invalid version advertisement message")?;

            let version = message
                .body
                .into_version()
                .map_err(|actual| eyre!("expected version advertisement, got {actual:?}"))?;

            info!(
                network = message.network,
                ?version,
                "received advertisement"
            );

            transport
                .send(Message {
                    network: Magic::Main as _,
                    body: MessageBody::Verack,
                })
                .await
                .wrap_err("couldn't send verack")?;

            info!("sent verack");

            let message = transport
                .next()
                .await
                .wrap_err("transport closed bofer verack received")?
                .wrap_err("peer sent invalid verack")?;

            if !message.body.is_verack() {
                bail!("expected verack, got {:?}", message.body)
            }

            info!(network = message.network, "received verack");
            info!("handshake complete!");
            Ok(())
        }
    }
}

fn current_unix_secs() -> i64 {
    time::SystemTime::now()
        .duration_since(time::SystemTime::UNIX_EPOCH)
        .expect("too far in the past!")
        .as_secs()
        .try_into()
        .expect("time is too big!")
}
