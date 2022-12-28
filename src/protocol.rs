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
//
// Goals for this module are
// - be fairly direct translations of the bitcoin documentations
// - minimise the number of manual implementations, while still being correct
// - allow zero-copy borrows from the source data
//   - we achieve this with &strs, but not other structs
//   - we could have safe "view structs" into owned buffers, but I'd only stoop to that in extreme
//     performance environments
mod wire {
    use nom::Parser as _;
    use nom_supreme::ParserExt as _;
    use tap::Tap;
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
            impl<'__input, $($struct_lifetime,)? IResultErrT: ParseError<'__input>> Transcode<'__input, IResultErrT> for $struct_name$(<$struct_lifetime>)?
            $( // allow struct_lifetime to have its own name
                where
                    $struct_lifetime: '__input,
                    '__input: $struct_lifetime,
            )?
            {
                fn parse(
                    input: &'__input [u8],
                ) -> nom::IResult<&'__input [u8], $struct_name$(<$struct_lifetime>)?, IResultErrT> {
                    nom::sequence::tuple((
                        // We must refer to $field_ty here to get the macro to repeat as desired
                        $(<$field_ty as Transcode<IResultErrT>>::parse,)*
                    )).map(
                        |(
                            $($field_name,)*
                        )| $struct_name {
                            $($field_name,)*
                        },
                    )
                    .parse(input)
                }

                fn deparsed_len(&self) -> usize {
                    [
                        $(<$field_ty as Transcode<IResultErrT>>::deparsed_len(&self.$field_name),)*
                    ].into_iter().sum()
                }
                fn deparse(&self, output: &mut [u8]) {
                    $(let output = <$field_ty as TranscodeExt<IResultErrT>>::deparse_into_and_advance(
                        &self.$field_name,
                        output
                    );)*
                    let _ = output;
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
        pub services: U64le,
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

    transcode_each_field! {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, zerocopy::AsBytes, zerocopy::FromBytes)]
        #[repr(C)]
        pub struct VersionBasic {
            pub fields_mandatory: VersionFieldsMandatory,
        }
    }

    transcode_each_field! {
        #[derive(Debug, Clone, PartialEq, Hash)]
        pub struct Version106<'a> {
            pub fields_mandatory: VersionFieldsMandatory,
            pub fields_106: VersionFields106<'a>,
        }
    }

    transcode_each_field! {
        #[derive(Debug, Clone, PartialEq, Hash)]
        pub struct Version70001<'a> {
            pub fields_mandatory: VersionFieldsMandatory,
            pub fields_106: VersionFields106<'a>,
            pub fields_70001: VersionFields70001,
        }
    }

    #[derive(Debug, Clone, PartialEq, Hash)]
    pub enum Version<'a> {
        Basic(VersionBasic),
        Supports106(Version106<'a>),
        Supports70001(Version70001<'a>),
    }

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

    /// Common constraint for [nom::IResult]'s error type.
    /// This is a single place to add further errors, and allows us to compose parsing automatically
    pub trait ParseError<'a>:
        nom::error::ParseError<&'a [u8]>
        + nom::error::FromExternalError<&'a [u8], std::str::Utf8Error>
    {
    }
    impl<'a, T> ParseError<'a> for T where
        T: nom::error::ParseError<&'a [u8]>
            + nom::error::FromExternalError<&'a [u8], std::str::Utf8Error>
    {
    }

    /// Decoded and encoded this struct on the wire according to the bitcoin protocol.
    pub trait Transcode<'a, IResultErrT: ParseError<'a>> {
        /// Attempt to deserialize this struct.
        fn parse(input: &'a [u8]) -> nom::IResult<&'a [u8], Self, IResultErrT>
        where
            Self: Sized;
        /// The length of this struct when serialized.
        fn deparsed_len(&self) -> usize;
        /// Deserialise this struct.
        /// # Panics
        /// Implementations may panic if `output.len() < self.deparsed_len()`
        fn deparse(&self, output: &mut [u8]);
    }

    trait TranscodeExt<'a, IResultErrT: ParseError<'a>>: Transcode<'a, IResultErrT> {
        fn deparse_into_and_advance<'output>(
            &self,
            output: &'output mut [u8],
        ) -> &'output mut [u8] {
            self.deparse(output);
            &mut output[self.deparsed_len()..]
        }
        fn deparse_to_vec(&self) -> Vec<u8> {
            vec![0u8; self.deparsed_len()].tap_mut(|it| self.deparse(it))
        }
    }

    impl<'a, IResultErrT: ParseError<'a>, T> TranscodeExt<'a, IResultErrT> for T where
        T: Transcode<'a, IResultErrT>
    {
    }

    impl<'a, IResultErrT: ParseError<'a>> Transcode<'a, IResultErrT> for bool {
        fn parse(input: &'a [u8]) -> nom::IResult<&'a [u8], Self, IResultErrT> {
            use nom::bytes::streaming::tag;
            tag(&[0x00])
                .value(false)
                .or(tag(&[0x01]).value(true))
                .parse(input)
        }

        fn deparsed_len(&self) -> usize {
            std::mem::size_of::<Self>()
        }

        fn deparse(&self, output: &mut [u8]) {
            self.write_to_prefix(output)
                .expect("attempted to deparse into a buffer too small for bool")
        }
    }

    impl<'a, IResultErrT: ParseError<'a>> Transcode<'a, IResultErrT> for VarInt {
        fn parse(input: &'a [u8]) -> nom::IResult<&'a [u8], Self, IResultErrT> {
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

        fn deparsed_len(&self) -> usize {
            // a more direct translation of protocol documentation
            #[allow(clippy::match_overlapping_arm)]
            match self.0 {
                ..=0xFE => 1,
                ..=0xFFFF => 3,
                ..=0xFFFF_FFFF => 5,
                _ => 9,
            }
        }
        fn deparse(&self, output: &mut [u8]) {
            if let None = match self.0 {
                small @ ..=0xFE => {
                    output[0] = small as u8;
                    Some(())
                }
                medium @ ..=0xFFFF => {
                    output[0] = 0xFD;
                    U16le::new(medium as _).write_to_prefix(&mut output[1..])
                }
                large @ ..=0xFFFF_FFFF => {
                    output[0] = 0xFE;
                    U32le::new(large as _).write_to_prefix(&mut output[1..])
                }
                xlarge => {
                    output[0] = 0xFF;
                    U64le::new(xlarge as _).write_to_prefix(&mut output[1..])
                }
            } {
                panic!("attempted to deparse into a buffer too small for VarInt")
            }
        }
    }

    impl<'a, IResultErrT: ParseError<'a>> Transcode<'a, IResultErrT> for VarStr<'a> {
        fn parse(input: &'a [u8]) -> nom::IResult<&'a [u8], VarStr<'a>, IResultErrT> {
            let (rem, len) = VarInt::parse(input)?;
            nom::bytes::streaming::take(len.0)
                .map_res(std::str::from_utf8)
                .map(VarStr)
                .parse(rem)
        }

        fn deparsed_len(&self) -> usize {
            <VarInt as Transcode<IResultErrT>>::deparsed_len(&self.len_var_int()) + self.0.len()
        }
        fn deparse(&self, output: &mut [u8]) {
            let output = <VarInt as TranscodeExt<IResultErrT>>::deparse_into_and_advance(
                &self.len_var_int(),
                output,
            );
            self.0.write_to_prefix(output).unwrap()
        }
    }

    impl<'a, IResultErrT: ParseError<'a>> Transcode<'a, IResultErrT> for Version<'a> {
        fn parse(input: &'a [u8]) -> nom::IResult<&'a [u8], Self, IResultErrT> {
            nom::branch::alt((
                VersionBasic::parse
                    .verify(|v| v.fields_mandatory.version.get() < 106)
                    .map(Self::Basic),
                Version106::parse
                    .verify(|v| v.fields_mandatory.version.get() < 70001)
                    .map(Self::Supports106),
                Version70001::parse.map(Self::Supports70001),
            ))
            .parse(input)
        }

        fn deparsed_len(&self) -> usize {
            match self {
                Version::Basic(v) => <VersionBasic as Transcode<IResultErrT>>::deparsed_len(v),
                Version::Supports106(v) => <Version106 as Transcode<IResultErrT>>::deparsed_len(v),
                Version::Supports70001(v) => {
                    <Version70001 as Transcode<IResultErrT>>::deparsed_len(v)
                }
            }
        }

        fn deparse(&self, output: &mut [u8]) {
            match self {
                Version::Basic(v) => <VersionBasic as Transcode<IResultErrT>>::deparse(v, output),
                Version::Supports106(v) => {
                    <Version106 as Transcode<IResultErrT>>::deparse(v, output)
                }
                Version::Supports70001(v) => {
                    <Version70001 as Transcode<IResultErrT>>::deparse(v, output)
                }
            }
        }
    }

    /// Transcode using [zerocopy::FromBytes]/[zerocopy::AsBytes]
    macro_rules! transcode_primitive {
        ($($ty:ty $({ $array_len:ident })?),* $(,)?) => {
            $(
                #[automatically_derived]
                impl<'a, IResultErrT: ParseError<'a> $(, const $array_len: usize)?> Transcode<'a, IResultErrT> for $ty {
                    fn parse(input: &'a [u8]) -> nom::IResult<&'a[u8], Self, IResultErrT> {
                        match <$ty as zerocopy::FromBytes>::read_from_prefix(input) {
                            Some(t) => Ok((&input[std::mem::size_of::<$ty>()..], t)),
                            None => Err(nom::Err::Incomplete(nom::Needed::new(
                                input.len() - std::mem::size_of::<$ty>(),
                            ))),
                        }
                    }

                    fn deparsed_len(&self) -> usize {
                        std::mem::size_of::<$ty>()
                    }

                    fn deparse(&self, buffer: &mut [u8]) {
                        <$ty as zerocopy::AsBytes>::write_to_prefix(self, buffer)
                            .expect(concat!(
                                "attempted to deparse into a buffer too small for ",
                                stringify!($ty)
                            ))
                    }
                }
            )*
        };
    }

    transcode_primitive!(U32le, U64le, U128netwk, U16netwk, I32le, I64le, [u8; N] { N });

    #[cfg(test)]
    mod transcoding {
        use nom::Parser;
        use tap::Conv;

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
            T: PartialEq + fmt::Debug + Transcode<'example, nom::error::Error<&'example [u8]>>,
        {
            use pretty_assertions::assert_eq;

            let (_, parsed_bin) = T::parse
                .all_consuming()
                .parse(example_bin)
                .expect("failed to completely parse the example");

            assert_eq!(
                expected, parsed_bin,
                "the parsed example text doesn't match the expected struct"
            );

            assert_eq!(
                example_bin,
                expected.deparse_to_vec(),
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

        #[test]
        fn version() {
            do_test(
                &hex2bin([
                    "62 EA 00 00",             // - 60002 (protocol version 60002)
                    "01 00 00 00 00 00 00 00", // - 1 (NODE_NETWORK services)
                    "11 B2 D0 50 00 00 00 00", // - Tue Dec 18 10:12:33 PST 2012
                    "01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 FF FF 00 00 00 00 00 00", // - Recipient address info - see Network Address
                    "01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 FF FF 00 00 00 00 00 00", // - Sender address info - see Network Address
                    "3B 2E B3 5D 8C E6 17 65", // - Node ID
                    "0F 2F 53 61 74 6F 73 68 69 3A 30 2E 37 2E 32 2F", // - "/Satoshi:0.7.2/" sub-version string (string is 15 bytes long)
                    "C0 3E 03 00", // - Last block sending node has is block #212672
                ]),
                Version::Supports106(Version106 {
                    fields_mandatory: VersionFieldsMandatory {
                        version: 60002.into(),
                        services: 1.into(),
                        timestamp: 1355854353.into(),
                        receiver: NetworkAddressWithoutTime {
                            services: 1.into(),
                            ipv6: std::net::Ipv4Addr::UNSPECIFIED
                                .to_ipv6_mapped()
                                .conv::<u128>()
                                .into(),
                            port: 0.into(),
                        },
                    },
                    fields_106: VersionFields106 {
                        sender: NetworkAddressWithoutTime {
                            services: 1.into(),
                            ipv6: std::net::Ipv4Addr::UNSPECIFIED
                                .to_ipv6_mapped()
                                .conv::<u128>()
                                .into(),
                            port: 0.into(),
                        },
                        nonce: 7284544412836900411.into(),
                        user_agent: VarStr("/Satoshi:0.7.2/"),
                        start_height: 212672.into(),
                    },
                }),
            );
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
