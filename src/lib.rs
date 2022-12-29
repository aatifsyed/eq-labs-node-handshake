pub mod wire;

use std::{cmp, io, mem};

use bitcoin_hashes::Hash as _;
use bytes::Buf as _;
use nom::Parser;
use nom_supreme::ParserExt;
use zerocopy::FromBytes as _;

use crate::wire::Transcode as _;

#[derive(Debug, Clone, PartialEq, Hash)]
pub struct Message {
    pub network: u32,
    pub body: MessageBody,
}

#[derive(Debug, Clone, PartialEq, Hash, enum_as_inner::EnumAsInner)]
pub enum MessageBody {
    Verack,
    Version(wire::Version<'static>),
}

pub struct Encoder {}

#[derive(Debug, thiserror::Error)]
pub enum EncoderError {
    #[error(transparent)]
    IoError(#[from] io::Error),
}

impl tokio_util::codec::Encoder<Message> for Encoder {
    type Error = EncoderError;

    #[tracing::instrument(level = "debug", skip(self, output), ret, err)]
    fn encode(&mut self, item: Message, output: &mut bytes::BytesMut) -> Result<(), Self::Error> {
        let with_command = |command| wire::Header {
            magic: item.network.into(),
            command,
            ..wire::Header::new_zeroed()
        };
        use crate::constants::commands::arr::{VERACK, VERSION};
        match item.body {
            MessageBody::Verack => wire::Frame {
                header: with_command(VERACK),
                body: (),
            }
            .deparse_valid_into(output),
            MessageBody::Version(body) => wire::Frame {
                header: with_command(VERSION),
                body,
            }
            .deparse_valid_into(output),
        }
        Ok(())
    }
}

pub struct Decoder {
    /// Maximum frame length to allow.
    /// Since [wire::VarStr]'s borrow from the input, this is implicitly an upper bound on heap allocations
    pub max_frame_length: Option<u32>,
}

#[derive(Debug, thiserror::Error)]
pub enum DecoderError {
    #[error("error parsing payload for {command} frame: {message}")]
    PayloadParsingError {
        command: crate::constants::commands::Command,
        message: String,
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

    #[tracing::instrument(level = "debug", skip(self, src), ret, err)]
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
        let expected_checksum = {
            let c = bitcoin_hashes::sha256d::Hash::hash(&payload).into_inner();
            [c[0], c[1], c[2], c[3]]
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
            Version => match wire::Version::parse::<nom::error::VerboseError<_>>
                .all_consuming()
                .parse(&payload)
            {
                Ok((_, version)) => Ok(Some(Message {
                    network: header.magic.get(),
                    // Here is where we make the call to heap allocate - a high performance implementation could choose not to
                    body: MessageBody::Version(version.into_static()),
                })),
                Err(nom::Err::Incomplete(_)) => unreachable!("called all_consuming()"),
                Err(nom::Err::Error(error)) => Err(DecoderError::PayloadParsingError {
                    command,
                    message: format!("{error:?}"),
                }),
                Err(nom::Err::Failure(error)) => Err(DecoderError::PayloadParsingError {
                    command,
                    message: format!("{error:?}"),
                }),
            },
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

/// Simple struct which unifies an encoder and decoder
#[derive(Debug, Clone, Copy)]
pub struct Codec<EncoderT, DecoderT> {
    pub encoder: EncoderT,
    pub decoder: DecoderT,
}

impl<EncoderT, DecoderT> Codec<EncoderT, DecoderT> {
    pub fn new(encoder: EncoderT, decoder: DecoderT) -> Self {
        Self { encoder, decoder }
    }
}

impl<EncoderT, DecoderT, EncodeItemT> tokio_util::codec::Encoder<EncodeItemT>
    for Codec<EncoderT, DecoderT>
where
    EncoderT: tokio_util::codec::Encoder<EncodeItemT>,
{
    type Error = EncoderT::Error;

    fn encode(&mut self, item: EncodeItemT, dst: &mut bytes::BytesMut) -> Result<(), Self::Error> {
        self.encoder.encode(item, dst)
    }
}

impl<EncoderT, DecoderT> tokio_util::codec::Decoder for Codec<EncoderT, DecoderT>
where
    DecoderT: tokio_util::codec::Decoder,
{
    type Item = DecoderT::Item;

    type Error = DecoderT::Error;

    fn decode(&mut self, src: &mut bytes::BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        self.decoder.decode(src)
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

    #[derive(
        Debug,
        Clone,
        Copy,
        PartialEq,
        Eq,
        Hash,
        bitbag::BitBaggable,
        strum::EnumIter,
        strum::Display,
    )]
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

    #[cfg(test)]
    #[test]
    fn services_non_overapping() {
        bitbag::BitBag::<Services>::check_nonoverlapping().unwrap()
    }

    #[derive(
        Debug,
        Clone,
        Copy,
        PartialEq,
        Eq,
        Hash,
        num_enum::TryFromPrimitive,
        num_enum::IntoPrimitive,
        strum::Display,
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
