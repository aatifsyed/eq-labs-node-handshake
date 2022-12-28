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

/// Wire representations.
/// Endianness conversions are not done while parsing for the most part, we just store that information in the type system.
///
/// Almost all integers are encoded in little endian. Only IP or port number are encoded big endian. All field sizes are numbers of bytes.
// https://en.bitcoin.it/wiki/Protocol_documentation#Common_structures
mod wire {
    use nom_supreme::ParserExt as _;
    use zerocopy::{
        little_endian::{I32 as I32le, I64 as I64le, U16 as U16le, U32 as U32le, U64 as U64le},
        network_endian::{U128 as U128netwk, U16 as U16netwk},
        AsBytes,
    };

    // bargain bucket derive macro
    macro_rules! transcode_each_field {
        // Capture struct definition
        (
            $(#[$struct_meta:meta])*
            $struct_vis:vis struct $struct_name:ident$(<$struct_lifetime:lifetime>)? {
                $(
                    $(#[$field_meta:meta])*
                    $field_vis:vis $field_name:ident: $field_ty:ty,
                )*
            }
        ) => {
            // Passthrough the struct definition
            $(#[$struct_meta])*
            $struct_vis struct $struct_name$(<$struct_lifetime>)? {
                $(
                    $(#[$field_meta])*
                    $field_vis $field_name: $field_ty,
                )*
            }

            #[automatically_derived]
            impl<'__input, $($struct_lifetime,)? IResultErrT> nom::Parser<&'__input [u8], $struct_name$(<$struct_lifetime>)?, IResultErrT> for Transcoder
            where
                $( // allow struct_lifetime to have its own name
                    $struct_lifetime: '__input,
                    '__input: $struct_lifetime,
                )?
                // common bounds
                IResultErrT: nom::error::ParseError<&'__input [u8]>
                    + nom::error::FromExternalError<&'__input [u8], std::str::Utf8Error>,
            {
                fn parse(
                    &mut self, input: &'__input [u8],
                ) -> nom::IResult<&'__input [u8], $struct_name$(<$struct_lifetime>)?, IResultErrT> {
                    nom::sequence::tuple((
                        // We must refer to $field_ty here to get the macro to repeat as desired
                        $(Self::parser_for::<$field_ty, IResultErrT>(),)*
                    )).map(
                        |(
                            $($field_name,)*
                        )| $struct_name {
                            $($field_name,)*
                        },
                    )
                    .parse(input)
                }
            }

            #[automatically_derived]
            impl$(<$struct_lifetime>)? Deparse<$struct_name$(<$struct_lifetime>)?> for Transcoder {
                fn deparsed_len(out: &$struct_name$(<$struct_lifetime>)?) -> usize {
                    [
                        $(<Self as Deparse<$field_ty>>::deparsed_len(&out.$field_name),)*
                    ].into_iter().sum()
                }
                fn deparse(out: &$struct_name$(<$struct_lifetime>)?, buffer: &mut [u8]) {
                    $(let buffer = Self::deparse_into_and_advance(&out.$field_name, buffer);)*
                    let _ = buffer;
                }
            }
        };
    }

    transcode_each_field! {
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
    }}

    transcode_each_field! {
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
    }}

    transcode_each_field! {
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
    }}

    transcode_each_field! {
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
    }}

    transcode_each_field! {
    /// Fields present in all version packets at or after version 70001
    // https://en.bitcoin.it/wiki/Protocol_documentation#version
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, zerocopy::AsBytes)]
    #[repr(C)]
    pub struct VersionFields70001 {
        /// Whether the remote peer should announce relayed transactions or not, see BIP 0037
        pub relay: bool,
    }}

    /// Integer can be encoded depending on the represented value to save space.
    /// Variable length integers always precede an array/vector of a type of data that may vary in length.
    /// Longer numbers are encoded in little endian.
    // https://en.bitcoin.it/wiki/Protocol_documentation#Variable_length_integer
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct VarInt(pub u64);

    impl<T> From<T> for VarInt
    where
        T: Into<u64>,
    {
        fn from(value: T) -> Self {
            Self(value.into())
        }
    }

    /// Variable length string can be stored using a variable length integer followed by the string itself.
    // https://en.bitcoin.it/wiki/Protocol_documentation#Variable_length_string
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct VarStr<'a>(pub &'a str);

    impl VarStr<'_> {
        /// # Panics
        /// If `self.0.len() > u64::MAX`
        pub fn len_var_int(&self) -> VarInt {
            VarInt(self.0.len().try_into().expect("very large string"))
        }
    }

    /// Implements nom::Parser for structs according to bitcoin's wire protocol
    // Keeping all implementations on this struct simplifies lifetimes for borrowed data,
    // ultimately allowing us to zerocopy for [VarStr] - see repo history.
    //
    // We could keep state on the Transcoder if we wanted to parameterise e.g maximum string lengths
    struct Transcoder;

    /// Serialize this `OutT` in accordance to the bitcoin protocol.
    // This trait and its implementors are broadly inspired by fuschia's netstack3 traits, which do a
    // kind of inside-out packet parsing.
    // See https://github.com/aatifsyed/fuschia-nestack-hacking.
    pub trait Deparse<OutT> {
        /// The size of buffer required to deparse this struct (including all fields).
        /// MUST be equal to the number of bytes deparsed into `buffer` in [Deparse::deparse].
        fn deparsed_len(out: &OutT) -> usize;
        /// Deparse this struct into a buffer.
        /// Implementations may assume that `buffer.len() >= self.deparsed_len()`.
        fn deparse(out: &OutT, buffer: &mut [u8]);
    }

    /// Transcode using [zerocopy::FromBytes]/[zerocopy::AsBytes]
    macro_rules! transcode_primitive {
        ($($ty:ty $({ $array_len:ident })?),* $(,)?) => {
            $(
                #[automatically_derived]
                impl<'a, IResultErrT $(, const $array_len: usize)?> nom::Parser<&'a [u8], $ty, IResultErrT> for Transcoder {
                    fn parse(&mut self, input: &'a [u8]) -> nom::IResult<&'a [u8], $ty, IResultErrT> {
                        match <$ty as zerocopy::FromBytes>::read_from_prefix(input) {
                            Some(t) => Ok((&input[std::mem::size_of::<$ty>()..], t)),
                            None => Err(nom::Err::Incomplete(nom::Needed::new(
                                input.len() - std::mem::size_of::<$ty>(),
                            ))),
                        }
                    }
                }

                #[automatically_derived]
                impl$(<const $array_len: usize>)? Deparse<$ty> for Transcoder {
                    fn deparsed_len(_: &$ty) -> usize {
                        std::mem::size_of::<$ty>()
                    }
                    fn deparse(out: &$ty, buffer: &mut [u8]) {
                        <$ty as zerocopy::AsBytes>::write_to_prefix(out, buffer)
                            .expect(concat!(
                                "Transcoder attempted to deparse into a buffer too small for ",
                                stringify!($ty)
                            ))
                    }
                }
            )*
        };
    }

    transcode_primitive!(U32le, U64le, U128netwk, U16netwk, I32le, I64le, [u8; N] { N });

    impl<'a, IResultErrT> nom::Parser<&'a [u8], bool, IResultErrT> for Transcoder
    where
        IResultErrT: nom::error::ParseError<&'a [u8]>,
    {
        fn parse(&mut self, input: &'a [u8]) -> nom::IResult<&'a [u8], bool, IResultErrT> {
            use nom::bytes::streaming::tag;
            tag(&[0x00])
                .value(false)
                .or(tag(&[0x01]).value(true))
                .parse(input)
        }
    }

    impl Deparse<bool> for Transcoder {
        fn deparsed_len(_: &bool) -> usize {
            std::mem::size_of::<bool>()
        }
        fn deparse(out: &bool, buffer: &mut [u8]) {
            <bool as zerocopy::AsBytes>::write_to_prefix(out, buffer)
                .expect("Transcoder attempted to deparse into a buffer too small for bool")
        }
    }

    impl<'a, IResultErrT> nom::Parser<&'a [u8], VarInt, IResultErrT> for Transcoder
    where
        IResultErrT: nom::error::ParseError<&'a [u8]>,
    {
        fn parse(&mut self, input: &'a [u8]) -> nom::IResult<&'a [u8], VarInt, IResultErrT> {
            use nom::{
                bytes::streaming::tag,
                number::streaming::{le_u16, le_u32, le_u64, le_u8},
                sequence::preceded,
            };
            nom::combinator::fail
                .or(preceded(tag(&[0xFF]), le_u64)
                    .verify(|u| *u > u32::MAX.into())
                    .map(VarInt::from))
                .or(preceded(tag(&[0xFE]), le_u32)
                    .verify(|u| *u > u16::MAX.into())
                    .map(VarInt::from))
                .or(preceded(tag(&[0xFD]), le_u16)
                    .verify(|u| *u > u8::MAX.into())
                    .map(VarInt::from))
                .or(le_u8.map(VarInt::from))
                .parse(input)
        }
    }

    impl Deparse<VarInt> for Transcoder {
        fn deparsed_len(out: &VarInt) -> usize {
            // a more direct translation of protocol documentation
            #[allow(clippy::match_overlapping_arm)]
            match out.0 {
                ..=0xFE => 1,
                ..=0xFFFF => 3,
                ..=0xFFFF_FFFF => 5,
                _ => 9,
            }
        }
        fn deparse(out: &VarInt, buffer: &mut [u8]) {
            match out.0 {
                small @ ..=0xFE => buffer[0] = small as u8,
                medium @ ..=0xFFFF => {
                    buffer[0] = 0xFD;
                    U16le::new(medium as _).write_to_prefix(&mut buffer[1..]);
                }
                large @ ..=0xFFFF_FFFF => {
                    buffer[0] = 0xFE;
                    U32le::new(large as _).write_to_prefix(&mut buffer[1..]);
                }
                xlarge => {
                    buffer[0] = 0xFF;
                    U64le::new(xlarge as _).write_to_prefix(&mut buffer[1..]);
                }
            }
        }
    }

    impl<'a, IResultErrT> nom::Parser<&'a [u8], VarStr<'a>, IResultErrT> for Transcoder
    where
        IResultErrT: nom::error::ParseError<&'a [u8]>
            + nom::error::FromExternalError<&'a [u8], std::str::Utf8Error>,
    {
        fn parse(&mut self, input: &'a [u8]) -> nom::IResult<&'a [u8], VarStr<'a>, IResultErrT> {
            let (rem, len) = Self::parser_for::<VarInt, _>().parse(input)?;
            nom::bytes::streaming::take(len.0)
                .map_res(std::str::from_utf8)
                .map(VarStr)
                .parse(rem)
        }
    }

    impl Transcoder {
        /// Implementation detail of [transcode_each_field]
        fn parser_for<'a, T, IResultErrT>() -> impl nom::Parser<&'a [u8], T, IResultErrT>
        where
            Self: nom::Parser<&'a [u8], T, IResultErrT>,
        {
            Self
        }

        fn deparse_into_and_advance<'buffer, OutT>(
            out: &OutT,
            buffer: &'buffer mut [u8],
        ) -> &'buffer mut [u8]
        where
            Self: Deparse<OutT>,
        {
            Self::deparse(out, buffer);
            &mut buffer[Self::deparsed_len(out)..]
        }
    }

    impl Deparse<VarStr<'_>> for Transcoder {
        fn deparsed_len(out: &VarStr<'_>) -> usize {
            <Self as Deparse<VarInt>>::deparsed_len(&out.len_var_int()) + out.0.len()
        }
        fn deparse(out: &VarStr<'_>, buffer: &mut [u8]) {
            let buffer = Self::deparse_into_and_advance(&out.len_var_int(), buffer);
            out.0.write_to_prefix(buffer).unwrap()
        }
    }

    #[cfg(test)]
    mod transcoding {
        use nom::Parser;

        use super::*;
        use std::fmt;

        fn hex2bin<'a>(hex: impl IntoIterator<Item = &'a str>) -> Vec<u8> {
            use tap::Pipe;
            hex.into_iter()
                .flat_map(str::chars)
                .filter(char::is_ascii_alphanumeric)
                .collect::<String>()
                .pipe(hex::decode)
                .expect("invalid hex")
        }

        fn do_test<'example, T>(example_bin: &'example [u8], expected: T)
        where
            T: PartialEq + fmt::Debug,
            Transcoder:
                nom::Parser<&'example [u8], T, nom::error::Error<&'example [u8]>> + Deparse<T>,
        {
            use pretty_assertions::assert_eq;

            let (_, parsed_bin) = Transcoder.all_consuming().parse(example_bin).unwrap();

            assert_eq!(
                expected, parsed_bin,
                "the parsed example text doesn't match the expected struct"
            );

            let mut unparsed_bin = vec![0u8; Transcoder::deparsed_len(&expected)];
            Transcoder::deparse(&expected, &mut unparsed_bin);
            assert_eq!(
                example_bin, unparsed_bin,
                "the unparsed struct doesn't match the example bin"
            );
        }

        #[test]
        fn header() {
            do_test(
                &hex2bin([
                    "F9 BE B4 D9",                         // - Main network magic bytes
                    "76 65 72 73 69 6F 6E 00 00 00 00 00", // - "version" command
                    "64 00 00 00",                         // - Payload is 100 bytes long
                    "35 8d 49 32", // - payload checksum (internal byte order)
                ]),
                Header {
                    magic: 0xD9B4BEF9.into(),
                    command: *b"version\0\0\0\0\0",
                    length: 100.into(),
                    checksum: [0x35, 0x8d, 0x49, 0x32],
                },
            )
        }

        #[test]
        fn var_str() {
            do_test(
                &hex2bin(["0F 2F 53 61 74 6F 73 68 69 3A 30 2E 37 2E 32 2F"]),
                VarStr("/Satoshi:0.7.2/"),
            );
            do_test(&[0x00], VarStr(""));
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
