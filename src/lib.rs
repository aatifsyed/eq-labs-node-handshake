pub mod wire;

use std::{cmp, io, mem};

use bitcoin_hashes::Hash as _;
use bytes::Buf as _;
use zerocopy::FromBytes as _;

pub struct Message {
    pub network: u32,
    pub body: MessageBody,
}

pub enum MessageBody {
    Verack,
    Version,
}

pub struct Encoder {}

#[derive(Debug, thiserror::Error)]
pub enum EncoderError {
    #[error(transparent)]
    IoError(#[from] io::Error),
}

impl tokio_util::codec::Encoder<Message> for Encoder {
    type Error = EncoderError;

    fn encode(&mut self, item: Message, dst: &mut bytes::BytesMut) -> Result<(), Self::Error> {
        todo!()
    }
}

pub struct Decoder {
    max_frame_length: Option<u32>,
}

#[derive(Debug, thiserror::Error)]
pub enum DecoderError {
    #[error("error parsing payload for {command} frame")]
    PayloadParsingError {
        command: crate::constants::commands::Command,
        error: nom::error::VerboseError<Vec<u8>>,
    },
    #[error("unexpected payload of length {payload_length} for {command} frame")]
    UnexpectedPayload {
        command: crate::constants::commands::Command,
        payload_length: usize,
    },
    #[error("frame length {advertised} is greated than threshold {threshold}")]
    RejectedFrameLength { advertised: u32, threshold: u32 },
    #[error("checksum failed for {command} frame with payload length {payload_length}")]
    ChecksumFailed {
        command: crate::constants::commands::Command,
        payload_length: usize,
    },
    #[error("unrecognised command string {0:?}")]
    UnrecognisedCommand([u8; 12]),
    #[error(transparent)]
    IoError(#[from] io::Error),
}

impl tokio_util::codec::Decoder for Decoder {
    type Item = Message;

    type Error = DecoderError;

    fn decode(&mut self, src: &mut bytes::BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // Read the header, or ask for more bytes
        let Some(header) = wire::Header::read_from_prefix(src.as_ref()) else {
            src.reserve(mem::size_of::<wire::Header>()); // preallocate room
            return Ok(None)
        };

        // Check for malicious header lengths
        if let Some(threshold) = self.max_frame_length {
            let advertised = header.length.get();
            if advertised > threshold {
                return Err(DecoderError::RejectedFrameLength {
                    advertised,
                    threshold,
                });
            }
        }

        // Check for a valid command string
        let command = crate::constants::commands::Command::try_from(header.command)
            .map_err(DecoderError::UnrecognisedCommand)?;

        // Get the whole frame
        static_assertions::const_assert!(mem::size_of::<usize>() >= mem::size_of::<u32>());
        let advertised_payload_length = header.length.get() as usize;
        let len_required = mem::size_of::<wire::Header>() + advertised_payload_length;
        let len_collected = src.len();

        let mut header_and_payload = match len_collected.cmp(&len_required) {
            cmp::Ordering::Less => {
                src.reserve(len_required - len_collected);
                return Ok(None);
            }
            // we have an entire frame - take it from the buffer
            cmp::Ordering::Equal => src.split(),
            // take just our frame from the buffer
            cmp::Ordering::Greater => src.split_to(len_required),
        };

        // We've already got a copy of the header on the stack, trim to the payload
        header_and_payload.advance(mem::size_of::<wire::Header>());
        let payload = header_and_payload;

        // Check the checksum
        let expected_checksum = match payload.is_empty() {
            true => [0; 4],
            false => {
                let it = bitcoin_hashes::sha256d::Hash::hash(&payload).into_inner();
                [it[0], it[1], it[2], it[3]]
            }
        };

        if expected_checksum != header.checksum {
            return Err(DecoderError::ChecksumFailed {
                command,
                payload_length: payload.len(),
            });
        }

        // Decode the payload
        use crate::constants::commands::Command::{Verack, Version};
        match command {
            Version => todo!(),
            Verack => match payload.is_empty() {
                true => Ok(Some(Message {
                    network: header.magic.get(),
                    body: MessageBody::Verack,
                })),
                false => Err(DecoderError::UnexpectedPayload {
                    command,
                    payload_length: payload.len(),
                }),
            },
        }
    }
}

pub mod constants {
    pub mod commands {
        use std::fmt;

        const fn splat_str_to_array<const N: usize>(s: &str) -> [u8; N] {
            let mut array = [0; N];
            assert!(s.len() <= N, "string is too big to fit into array");
            let mut pos = 0;
            while pos < s.len() {
                array[pos] = s.as_bytes()[pos];
                pos += 1;
            }
            array
        }

        macro_rules! commands {
            ($($name:ident/$variant:ident = $str:expr),* $(,)?) => {
                pub mod str {
                    $(pub const $name: &str = $str;)*
                }
                pub mod arr {
                    $(pub const $name: [u8; 12] = super::splat_str_to_array($str);)*
                }
                #[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
                pub enum Command {
                    $($variant,)*
                }
                #[automatically_derived]
                impl TryFrom<[u8; 12]> for Command {
                    type Error = [u8; 12];
                    fn try_from(candidate: [u8; 12]) -> Result<Self, Self::Error> {
                        match candidate {
                            $(arr::$name => Ok(Self::$variant),)*
                            other => Err(other),
                        }
                    }
                }
                #[automatically_derived]
                impl fmt::Display for Command {
                    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                        match self {
                            $(Self::$variant => f.write_str(str::$name),)*
                        }
                    }
                }
            };
        }
        commands!(VERSION / Version = "version", VERACK / Verack = "verack");
    }

    #[derive(Debug, bitbag::BitBaggable, Clone, Copy, PartialEq, Eq, Hash)]
    #[repr(u64)]
    pub enum Services {
        /// `NODE_NETWORK`
        /// This node can be asked for full blocks instead of just headers.
        NodeNetwork = 1,
        /// `NODE_GETUTXO`
        /// See BIP 0064.
        NodeGetutxo = 2,
        /// `NODE_BLOOM`
        /// See BIP 0111.
        NodeBloom = 4,
        /// `NODE_WITNESS`
        /// See BIP 0144.
        NodeWitness = 8,
        /// `NODE_XTHIN`
        /// Never formally proposed (as a BIP), and discontinued. Was historically sporadically seen on the network.
        NodeXthin = 16,
        /// `NODE_COMPACT_FILTERS`
        /// See BIP 0157.
        NodeCompactFilters = 64,
        /// `NODE_NETWORK_LIMITED`
        /// See BIP 0159.
        NodeNetworkLimited = 1024,
    }

    #[derive(
        Debug, Clone, Copy, PartialEq, Eq, Hash, num_enum::TryFromPrimitive, num_enum::IntoPrimitive,
    )]
    #[repr(u32)]
    pub enum Magic {
        Main = 0xD9B4BEF9,
        Testnet = 0xDAB5BFFA,
        Testnet3 = 0x0709110B,
        Signet = 0x40CF030A,
        Namecoin = 0xFEB4BEF9,
    }
}
