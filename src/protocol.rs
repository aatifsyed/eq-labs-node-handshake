use std::{cmp, io, mem};

use bitcoin_hashes::Hash as _;
use bytes::Buf as _;
use nom_supreme::ParserExt as _;
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
        command: constants::commands::Command,
        error: nom::error::VerboseError<Vec<u8>>,
    },
    #[error("unexpected payload of length {payload_length} for {command} frame")]
    UnexpectedPayload {
        command: constants::commands::Command,
        payload_length: usize,
    },
    #[error("frame length {advertised} is greated than threshold {threshold}")]
    RejectedFrameLength { advertised: u32, threshold: u32 },
    #[error("checksum failed for {command} frame with payload length {payload_length}")]
    ChecksumFailed {
        command: constants::commands::Command,
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
        let command = constants::commands::Command::try_from(header.command)
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
        use constants::commands::Command::{Verack, Version};
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

trait HasBitcoinProtocolParser<'a, IResultErrT>: Sized {
    type Parser: nom::Parser<&'a [u8], Self, IResultErrT>;
    fn parser() -> Self::Parser;
}

#[derive(Debug)]
struct FromBytesParser<FromBytesT>(std::marker::PhantomData<FromBytesT>);
impl<FromBytesT> Default for FromBytesParser<FromBytesT> {
    fn default() -> Self {
        Self(Default::default())
    }
}

impl<'a, FromBytesT, IResultErrT> nom::Parser<&'a [u8], FromBytesT, IResultErrT>
    for FromBytesParser<FromBytesT>
where
    FromBytesT: zerocopy::FromBytes,
{
    fn parse(&mut self, input: &'a [u8]) -> nom::IResult<&'a [u8], FromBytesT, IResultErrT> {
        match FromBytesT::read_from_prefix(input) {
            Some(t) => Ok((&input[mem::size_of::<FromBytesT>()..], t)),
            None => Err(nom::Err::Incomplete(nom::Needed::new(
                input.len() - mem::size_of::<FromBytesT>(),
            ))),
        }
    }
}

impl<'a, IResultErrT, FromBytesT> HasBitcoinProtocolParser<'a, IResultErrT> for FromBytesT
where
    FromBytesT: zerocopy::FromBytes,
{
    type Parser = FromBytesParser<FromBytesT>;
    fn parser() -> Self::Parser {
        Self::Parser::default()
    }
}

/// Wire representations.
///
/// Almost all integers are encoded in little endian. Only IP or port number are encoded big endian. All field sizes are numbers of bytes.
/// Endianness conversions are not done while parsing, we just store that information in the type system.
mod wire {
    use nom::Parser;
    pub use zerocopy::{
        little_endian::{I32 as I32le, I64 as I64le, U32 as U32le, U64 as U64le},
        network_endian::{U128 as U128netwk, U16 as U16netwk},
    };

    /// Message header for all bitcoin protocol packets
    // https://en.bitcoin.it/wiki/Protocol_documentation#Message_structure
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, zerocopy::AsBytes, zerocopy::FromBytes)]
    #[repr(C)]
    pub struct Header {
        /// Magic value indicating message origin network, and used to seek to next message when stream state is unknown
        pub magic: U32le,
        /// ASCII string identifying the packet content, NULL padded (non-NULL padding results in packet rejected)
        pub command: [u8; 12],
        /// Length of payload in number of bytes
        pub length: U32le,
        /// First 4 bytes of sha256(sha256(payload))
        pub checksum: [u8; 4],
    }

    /// When a network address is needed somewhere, this structure is used. Network addresses are not prefixed with a timestamp in the version message.
    // https://en.bitcoin.it/wiki/Protocol_documentation#Network_address
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, zerocopy::AsBytes, zerocopy::FromBytes)]
    #[repr(C)]
    pub struct NetworkAddressWithoutTime {
        /// same service(s) listed in version.
        pub services: U32le,
        /// IPv6 address. Network byte order. The original client only supported IPv4 and only read the last 4 bytes to get the IPv4 address. However, the IPv4 address is written into the message as a 16 byte IPv4-mapped IPv6 address
        /// (12 bytes 00 00 00 00 00 00 00 00 00 00 FF FF, followed by the 4 bytes of the IPv4 address).
        pub ipv6: U128netwk,
        /// port number, network byte order
        pub port: U16netwk,
    }

    /// Fields present in all version packets
    // https://en.bitcoin.it/wiki/Protocol_documentation#version
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, zerocopy::AsBytes, zerocopy::FromBytes)]
    #[repr(C)]
    pub struct VersionFieldsMandatory {
        /// Identifies protocol version being used by the node
        pub version: I32le,
        /// Bitfield of features to be enabled for this connection.
        pub services: U64le,
        /// Standard UNIX timestamp in seconds.
        pub timestamp: I64le,
        /// The network address of the node receiving this message.
        pub receiver: NetworkAddressWithoutTime,
    }

    /// Fields present in all version packets at or after version 106
    // https://en.bitcoin.it/wiki/Protocol_documentation#version
    #[derive(Debug, Clone, PartialEq, Hash)]
    #[repr(C)]
    pub struct VersionFields106<'a> {
        /// Field can be ignored.
        /// This used to be the network address of the node emitting this message, but most P2P implementations send 26 dummy bytes.
        /// The "services" field of the address would also be redundant with the second field of the version message.
        pub sender: NetworkAddressWithoutTime,
        /// Node random nonce, randomly generated every time a version packet is sent. This nonce is used to detect connections to self.
        pub nonce: U64le,
        /// User Agent (0x00 if string is 0 bytes long)
        pub user_agent: VarStr<'a>,
        /// The last block received by the emitting node
        pub start_height: U32le,
    }

    impl<'a, IResultErrT> super::HasBitcoinProtocolParser<'a, IResultErrT> for VersionFields106<'a>
    where
        IResultErrT: nom::error::ParseError<&'a [u8]>
            + nom::error::FromExternalError<&'a [u8], VarIntTooWide>
            + nom::error::FromExternalError<&'a [u8], std::str::Utf8Error>
            + 'a,
    {
        type Parser = Box<dyn nom::Parser<&'a [u8], Self, IResultErrT> + 'a>;

        fn parser() -> Self::Parser {
            Box::new(
                nom::sequence::tuple(
                    (
                        <NetworkAddressWithoutTime as super::HasBitcoinProtocolParser<
                            IResultErrT,
                        >>::parser(),
                        <U64le as super::HasBitcoinProtocolParser<IResultErrT>>::parser(),
                        <VarStr as super::HasBitcoinProtocolParser<IResultErrT>>::parser(),
                        <U32le as super::HasBitcoinProtocolParser<IResultErrT>>::parser(),
                    ),
                )
                .map(|(sender, nonce, user_agent, start_height)| Self {
                    sender,
                    nonce,
                    user_agent,
                    start_height,
                }),
            )
        }
    }

    /// Fields present in all version packets at or after version 70001
    // https://en.bitcoin.it/wiki/Protocol_documentation#version
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, zerocopy::AsBytes)]
    #[repr(C)]
    pub struct VersionFields70001 {
        /// Whether the remote peer should announce relayed transactions or not, see BIP 0037
        pub relay: bool,
    }

    /// Integer can be encoded depending on the represented value to save space.
    /// Variable length integers always precede an array/vector of a type of data that may vary in length.
    /// Longer numbers are encoded in little endian.
    // https://en.bitcoin.it/wiki/Protocol_documentation#Variable_length_integer
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct VarInt {
        pub inner: u64,
    }

    #[cfg(target_pointer_width = "64")]
    impl From<usize> for VarInt {
        fn from(value: usize) -> Self {
            Self {
                inner: value as u64,
            }
        }
    }

    #[derive(Debug, thiserror::Error)]
    #[error(
        "var_int with value {inner} was {actual_width} bytes wide encoded, but should have been stored in fewer bytes"
    )]
    pub struct VarIntTooWide {
        pub inner: u64,
        pub actual_width: usize,
    }

    #[derive(Debug, Default)]
    pub struct VarIntParser;

    /// Check that `inner` couldn't be be stored in `WidthT` bytes
    fn check_varint<WidthT>(inner: impl Into<u64>) -> Result<VarInt, VarIntTooWide>
    where
        WidthT: num::Bounded + Into<u64>,
    {
        let inner = inner.into();
        if inner > WidthT::max_value().into() {
            Ok(VarInt { inner })
        } else {
            Err(VarIntTooWide {
                inner,
                actual_width: std::mem::size_of::<WidthT>(),
            })
        }
    }

    impl<'a, IResultErrT> nom::Parser<&'a [u8], VarInt, IResultErrT> for VarIntParser
    where
        IResultErrT: nom::error::ParseError<&'a [u8]>
            + nom::error::FromExternalError<&'a [u8], VarIntTooWide>,
    {
        fn parse(&mut self, input: &'a [u8]) -> nom::IResult<&'a [u8], VarInt, IResultErrT> {
            use nom::{
                combinator::map_res,
                number::streaming::{le_u16, le_u32, le_u64, le_u8},
            };

            let (rem, first_byte) = le_u8(input)?;
            match first_byte {
                // 0xFF followed by the length as uint64_t
                0xFF => map_res(le_u64, check_varint::<u32>)(rem),
                // 0xFE followed by the length as uint32_t
                0xFE => map_res(le_u32, check_varint::<u16>)(rem),
                // 0xFD followed by the length as uint16_t
                0xFD => map_res(le_u16, |inner| {
                    let inner = inner.into();
                    if inner < 0xFD {
                        Err(VarIntTooWide {
                            inner,
                            actual_width: 2,
                        })
                    } else {
                        Ok(VarInt { inner })
                    }
                })(rem),
                inner => Ok((
                    rem,
                    VarInt {
                        inner: inner.into(),
                    },
                )),
            }
        }
    }

    impl<'a, IResultErrT> super::HasBitcoinProtocolParser<'a, IResultErrT> for VarInt
    where
        IResultErrT: nom::error::ParseError<&'a [u8]>
            + nom::error::FromExternalError<&'a [u8], VarIntTooWide>,
    {
        type Parser = VarIntParser;

        fn parser() -> Self::Parser {
            Self::Parser::default()
        }
    }

    /// Variable length string can be stored using a variable length integer followed by the string itself.
    // https://en.bitcoin.it/wiki/Protocol_documentation#Variable_length_string
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct VarStr<'a>(&'a str);

    #[derive(Debug, Default)]
    pub struct VarStrParser;

    impl<'a, IResultErrT> nom::Parser<&'a [u8], VarStr<'a>, IResultErrT> for VarStrParser
    where
        IResultErrT: nom::error::ParseError<&'a [u8]>
            + nom::error::FromExternalError<&'a [u8], VarIntTooWide>
            + nom::error::FromExternalError<&'a [u8], std::str::Utf8Error>,
    {
        fn parse(&mut self, input: &'a [u8]) -> nom::IResult<&'a [u8], VarStr<'a>, IResultErrT> {
            let (rem, length) =
                <VarInt as super::HasBitcoinProtocolParser<IResultErrT>>::parser().parse(input)?;
            let (rem, s) = nom::combinator::map_res(
                // should fail to compile on 32-bit platforms, as nom::traits::ToUsize isn't implemented for u64 on those platforms
                // so we should be arithmetically safe
                nom::bytes::streaming::take(length.inner),
                std::str::from_utf8,
            )(rem)?;
            Ok((rem, VarStr(s)))
        }
    }

    impl<'a, IResultErrT> super::HasBitcoinProtocolParser<'a, IResultErrT> for VarStr<'a>
    where
        IResultErrT: nom::error::ParseError<&'a [u8]>
            + nom::error::FromExternalError<&'a [u8], VarIntTooWide>
            + nom::error::FromExternalError<&'a [u8], std::str::Utf8Error>,
    {
        type Parser = VarStrParser;

        fn parser() -> Self::Parser {
            Self::Parser::default()
        }
    }
}

mod constants {
    /// Allow [MessageBody::command] and [Message::parse] to use the same arrays
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
}

mod dynamic {
    use nom::{
        combinator::map_res,
        number::streaming::{le_u16, le_u32, le_u64, le_u8},
    };

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct VarInt {
        pub inner: u64,
    }

    #[cfg(target_pointer_width = "64")]
    impl From<usize> for VarInt {
        fn from(value: usize) -> Self {
            Self {
                inner: value as u64,
            }
        }
    }

    #[derive(Debug, thiserror::Error)]
    #[error(
        "var_int with value {inner} was {actual_width} bytes wide encoded, but should have been stored in fewer bytes"
    )]
    pub struct VarIntTooWide {
        pub inner: u64,
        pub actual_width: usize,
    }

    /// Check that `inner` couldn't be be stored in `WidthT` bytes
    fn check_varint<WidthT>(inner: impl Into<u64>) -> Result<VarInt, VarIntTooWide>
    where
        WidthT: num::Bounded + Into<u64>,
    {
        let inner = inner.into();
        if inner > WidthT::max_value().into() {
            Ok(VarInt { inner })
        } else {
            Err(VarIntTooWide {
                inner,
                actual_width: std::mem::size_of::<WidthT>(),
            })
        }
    }

    fn parse_varint<'a, IResultErrT>(
        buffer: &'a [u8],
    ) -> nom::IResult<&'a [u8], VarInt, IResultErrT>
    where
        IResultErrT: nom::error::ParseError<&'a [u8]>
            + nom::error::FromExternalError<&'a [u8], VarIntTooWide>,
    {
        let (rem, first_byte) = le_u8(buffer)?;
        match first_byte {
            // 0xFF followed by the length as uint64_t
            0xFF => map_res(le_u64, check_varint::<u32>)(rem),
            // 0xFE followed by the length as uint32_t
            0xFE => map_res(le_u32, check_varint::<u16>)(rem),
            // 0xFD followed by the length as uint16_t
            0xFD => map_res(le_u16, |inner| {
                let inner = inner.into();
                if inner < 0xFD {
                    Err(VarIntTooWide {
                        inner,
                        actual_width: 2,
                    })
                } else {
                    Ok(VarInt { inner })
                }
            })(rem),
            inner => Ok((
                rem,
                VarInt {
                    inner: inner.into(),
                },
            )),
        }
    }

    #[cfg(test)]
    mod var_int_tests {
        use super::*;
        #[test]
        fn test_short() {
            let (rem, var_int) = parse_varint::<nom::error::Error<_>>(&[0xFC]).unwrap();
            assert_eq!(0, rem.len());
            assert_eq!(252, var_int.inner);
        }
        #[test]
        fn test_medium() {
            let (rem, var_int) = parse_varint::<nom::error::Error<_>>(&[0xFD, 0xFF, 0x01]).unwrap();
            assert_eq!(0, rem.len());
            assert_eq!(511, var_int.inner);

            parse_varint::<nom::error::Error<_>>(&[0xFD, 0x01, 0x00])
                .expect_err("01 should be stored as a byte");
        }
    }

    // impl Deparse for VarInt {
    //     fn deparsed_len(&self) -> usize {
    //         // a more direct translation of protocol documentation
    //         #[allow(clippy::match_overlapping_arm)]
    //         match self.inner {
    //             ..=0xFE => 1,
    //             ..=0xFFFF => 3,
    //             ..=0xFFFF_FFFF => 5,
    //             _ => 9,
    //         }
    //     }

    //     fn deparse(&self, buffer: &mut [u8]) {
    //         match self.inner {
    //             small @ ..=0xFE => buffer[0] = small as u8,
    //             medium @ ..=0xFFFF => {
    //                 buffer[0] = 0xFD;
    //                 frontfill(&u16::to_le_bytes(medium as _), &mut buffer[1..])
    //             }
    //             large @ ..=0xFFFF_FFFF => {
    //                 buffer[0] = 0xFE;
    //                 frontfill(&u32::to_le_bytes(large as _), &mut buffer[1..])
    //             }
    //             xlarge => {
    //                 buffer[0] = 0xFF;
    //                 frontfill(&u64::to_le_bytes(xlarge as _), &mut buffer[1..])
    //             }
    //         }
    //     }
    // }
}
