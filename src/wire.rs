//! Wire representations.
//! Endianness conversions are not done while parsing for the most part, we just store that information in the type system.
//!
//! Almost all integers are encoded in little endian. Only IP or port number are encoded big endian. All field sizes are numbers of bytes.
// https://en.bitcoin.it/wiki/Protocol_documentation#Common_structures
//
// Goals for this module are
// - be fairly direct translations of the bitcoin documentations
// - minimise the number of manual implementations, while still being correct
// - allow zero-copy borrows from the source data
//   - we achieve this with &strs, but not other structs
//   - we could have safe "view structs" into owned buffers, but I'd only stoop to that in extreme
//     performance environments

use std::{borrow::Cow, fmt, net};

use nom::Parser as _;
use nom_supreme::ParserExt as _;
use tap::{Conv as _, Tap as _, TryConv as _};
use zerocopy::{
    little_endian::{I32 as I32le, I64 as I64le, U16 as U16le, U32 as U32le, U64 as U64le},
    network_endian::{U128 as U128netwk, U16 as U16netwk},
    AsBytes as _,
};

/// Decode and encode this struct on the wire according to the bitcoin protocol.
/// This is for bit interpretation and *not* validation, as far as possible.
// Generic over lifetime so we can impl for borrowed data
pub trait Transcode<'a> {
    /// Attempt to deserialize this struct.
    fn parse<IResultErrT: ParseError<'a>>(
        input: &'a [u8],
    ) -> nom::IResult<&'a [u8], Self, IResultErrT>
    where
        Self: Sized;
    /// The length of this struct when serialized.
    fn deparsed_len(&self) -> usize;
    /// Deserialise this struct.
    /// # Panics
    /// Implementations may panic if `output.len() < self.deparsed_len()`
    fn deparse(&self, output: &mut [u8]);
}

// bargain bucket derive macro
macro_rules! transcode_and_display_each_field {
    // Capture struct definition
    (
        $(#[$struct_meta:meta])*
        $struct_vis:vis struct $struct_name:ident$(<$struct_lifetime:lifetime>)? {
            $(
                $(#[$field_meta:meta])*
                $(@display($field_display_override:path))?
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
        impl<'__input, $($struct_lifetime)?> Transcode<'__input> for $struct_name$(<$struct_lifetime>)?
        $(
            // allow struct_lifetime to have its own name
            where
                $struct_lifetime: '__input,
                '__input: $struct_lifetime,
        )?
        {
            fn parse<IResultErrT: ParseError<'__input>>(
                input: &'__input [u8],
            ) -> nom::IResult<&'__input [u8], $struct_name$(<$struct_lifetime>)?, IResultErrT> {
                nom::sequence::tuple((
                    // We must refer to $field_ty here to get the macro to repeat as desired
                    $(<$field_ty as Transcode>::parse,)*
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
                    $(<$field_ty as Transcode>::deparsed_len(&self.$field_name),)*
                ].into_iter().sum()
            }
            fn deparse(&self, output: &mut [u8]) {
                $(let output = <$field_ty as TranscodeExt>::deparse_into_and_advance(
                    &self.$field_name,
                    output
                );)*
                let _ = output;
            }
        }

        #[automatically_derived]
        impl$(<$struct_lifetime>)? fmt::Display for $struct_name$(<$struct_lifetime>)? {
            #[allow(unreachable_patterns)]
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_struct(stringify!($struct_name))
                    $(
                        .field(stringify!($field_name), &match &self.$field_name {
                            $(
                                _ => format!("{:?}", $field_display_override(&self.$field_name)),
                            )?
                            _ => format!("{:?}", &self.$field_name),
                        })
                    )*
                    .finish()
            }
        }
    };
}

////////////////////////////////////////////////////////////////////////////////
// Structs transcribed from https://en.bitcoin.it/wiki/Protocol_documentation //
////////////////////////////////////////////////////////////////////////////////

transcode_and_display_each_field! {
/// Message header for all bitcoin protocol packets
// https://en.bitcoin.it/wiki/Protocol_documentation#Message_structure
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, zerocopy::AsBytes, zerocopy::FromBytes)]
#[repr(C)]
pub struct Header {
    /// Magic value indicating message origin network, and used to seek to next message when stream state is unknown
    @display(magic)
    pub magic: U32le,
    /// ASCII string identifying the packet content, NULL padded (non-NULL padding results in packet rejected)
    @display(command)
    pub command: [u8; 12],
    /// Length of payload in number of bytes
    pub length: U32le,
    /// First 4 bytes of sha256(sha256(payload))
    pub checksum: [u8; 4],
}}

fn forward(t: &(impl fmt::Display + Clone)) -> impl fmt::Debug {
    DebugWithDisplay(t.clone())
}

fn magic(u: &U32le) -> impl fmt::Debug {
    match crate::constants::Magic::try_from(u.get()) {
        Ok(known) => known.to_string(),
        Err(_) => u.to_string(),
    }
}

fn command(c: &[u8; 12]) -> impl fmt::Debug {
    match crate::constants::commands::Command::try_from(*c) {
        Ok(known) => known.to_string(),
        Err(_) => String::from_utf8_lossy(c).into_owned(),
    }
}

fn services(u: &U64le) -> impl fmt::Debug {
    bitbag::BitBag::<crate::constants::Services>::new_unchecked(u.get())
}

fn ipv6(u: &U128netwk) -> impl fmt::Debug {
    net::Ipv6Addr::from(u.get())
}

transcode_and_display_each_field! {
/// When a network address is needed somewhere, this structure is used. Network addresses are not prefixed with a timestamp in the version message.
// https://en.bitcoin.it/wiki/Protocol_documentation#Network_address
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, zerocopy::AsBytes, zerocopy::FromBytes)]
#[repr(C)]
pub struct NetworkAddressWithoutTime {
    /// same service(s) listed in version.
    @display(services)
    pub services: U64le,
    /// IPv6 address. Network byte order. The original client only supported IPv4 and only read the last 4 bytes to get the IPv4 address. However, the IPv4 address is written into the message as a 16 byte IPv4-mapped IPv6 address
    /// (12 bytes 00 00 00 00 00 00 00 00 00 00 FF FF, followed by the 4 bytes of the IPv4 address).
    @display(ipv6)
    pub ipv6: U128netwk,
    /// port number, network byte order
    pub port: U16netwk,
}}

impl NetworkAddressWithoutTime {
    pub fn new(services: u64, ip_address: net::IpAddr, port: u16) -> Self {
        Self {
            services: services.into(),
            ipv6: match ip_address {
                net::IpAddr::V4(v4) => v4.to_ipv6_mapped(),
                net::IpAddr::V6(v6) => v6,
            }
            .conv::<u128>()
            .into(),
            port: port.into(),
        }
    }
    pub fn ip_addr(&self) -> net::Ipv6Addr {
        self.ipv6.get().into()
    }
}

transcode_and_display_each_field! {
/// Fields present in all version packets
// https://en.bitcoin.it/wiki/Protocol_documentation#version
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, zerocopy::AsBytes, zerocopy::FromBytes)]
#[repr(C)]
pub struct VersionFieldsMandatory {
    /// Identifies protocol version being used by the node
    pub version: I32le,
    /// Bitfield of features to be enabled for this connection.
    @display(services)
    pub services: U64le,
    /// Standard UNIX timestamp in seconds.
    pub timestamp: I64le,
    /// The network address of the node receiving this message.
    @display(forward)
    pub receiver: NetworkAddressWithoutTime,
}}

transcode_and_display_each_field! {
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

impl VersionFields106<'_> {
    fn into_static(self) -> VersionFields106<'static> {
        let Self {
            sender,
            nonce,
            user_agent,
            start_height,
        } = self;
        VersionFields106 {
            sender,
            nonce,
            user_agent: user_agent.into_static(),
            start_height,
        }
    }
}

transcode_and_display_each_field! {
/// Fields present in all version packets at or after version 70001
// https://en.bitcoin.it/wiki/Protocol_documentation#version
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, zerocopy::AsBytes)]
#[repr(C)]
pub struct VersionFields70001 {
    /// Whether the remote peer should announce relayed transactions or not, see BIP 0037
    pub relay: bool,
}}

/////////////////////
// Fancier structs //
/////////////////////

/// Integer can be encoded depending on the represented value to save space.
/// Variable length integers always precede an array/vector of a type of data that may vary in length.
/// Longer numbers are encoded in little endian.
// https://en.bitcoin.it/wiki/Protocol_documentation#Variable_length_integer
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, derive_more::Display)]
pub struct VarInt(pub u64);

impl<T> From<T> for VarInt
where
    T: Into<u64>,
{
    fn from(value: T) -> Self {
        Self(value.into())
    }
}

impl<'a> Transcode<'a> for VarInt {
    fn parse<IResultErrT: ParseError<'a>>(
        input: &'a [u8],
    ) -> nom::IResult<&'a [u8], Self, IResultErrT> {
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
        if match self.0 {
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
        }
        .is_none()
        {
            panic!("attempted to deparse into a buffer too small for VarInt")
        }
    }
}

/// Variable length string can be stored using a variable length integer followed by the string itself.
// https://en.bitcoin.it/wiki/Protocol_documentation#Variable_length_string
// Putting a [Cow] in here is a little cheeky, but it allows us to use the same struct for protocol and business logic
#[derive(Debug, Clone, PartialEq, Eq, Hash, derive_more::Display)]
pub struct VarStr<'a>(pub Cow<'a, str>);

impl VarStr<'_> {
    pub fn borrowed(s: &str) -> VarStr<'_> {
        VarStr(Cow::Borrowed(s))
    }

    pub fn owned(s: impl Into<String>) -> VarStr<'static> {
        VarStr(Cow::Owned(s.into()))
    }

    pub fn into_static(self) -> VarStr<'static> {
        match self.0 {
            Cow::Borrowed(s) => VarStr(Cow::Owned(s.to_string())),
            Cow::Owned(s) => VarStr(Cow::Owned(s)),
        }
    }

    /// # Panics
    /// If `self.0.len() > u64::MAX`
    pub fn len_var_int(&self) -> VarInt {
        VarInt(self.0.len().try_into().expect("very large string"))
    }
}

impl<'a> Transcode<'a> for VarStr<'a> {
    fn parse<IResultErrT: ParseError<'a>>(
        input: &'a [u8],
    ) -> nom::IResult<&'a [u8], VarStr<'a>, IResultErrT> {
        let (rem, len) = VarInt::parse(input)?;
        nom::bytes::streaming::take(len.0)
            .map_res(std::str::from_utf8)
            .map(VarStr::owned)
            .parse(rem)
    }

    fn deparsed_len(&self) -> usize {
        self.len_var_int().deparsed_len() + self.0.len()
    }
    fn deparse(&self, output: &mut [u8]) {
        let output = self.len_var_int().deparse_into_and_advance(output);
        self.0.write_to_prefix(output).unwrap()
    }
}

transcode_and_display_each_field! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, zerocopy::AsBytes, zerocopy::FromBytes)]
    #[repr(C)]
    pub struct VersionBasic {
        pub fields_mandatory: VersionFieldsMandatory,
    }
}

transcode_and_display_each_field! {
    #[derive(Debug, Clone, PartialEq, Hash)]
    pub struct Version106<'a> {
        pub fields_mandatory: VersionFieldsMandatory,
        pub fields_106: VersionFields106<'a>,
    }
}

impl Version106<'_> {
    pub fn into_static(self) -> Version106<'static> {
        let Self {
            fields_mandatory,
            fields_106,
        } = self;
        Version106 {
            fields_mandatory,
            fields_106: fields_106.into_static(),
        }
    }
}

transcode_and_display_each_field! {
    #[derive(Debug, Clone, PartialEq, Hash)]
    pub struct Version70001<'a> {
        pub fields_mandatory: VersionFieldsMandatory,
        pub fields_106: VersionFields106<'a>,
        pub fields_70001: VersionFields70001,
    }
}
impl Version70001<'_> {
    pub fn into_static(self) -> Version70001<'static> {
        let Self {
            fields_mandatory,
            fields_106,
            fields_70001,
        } = self;
        Version70001 {
            fields_mandatory,
            fields_106: fields_106.into_static(),
            fields_70001,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Hash)]
pub enum Version<'a> {
    Basic(VersionBasic),
    Supports106(Version106<'a>),
    Supports70001(Version70001<'a>),
}

impl Version<'_> {
    pub fn into_static(self) -> Version<'static> {
        match self {
            Version::Basic(v) => Version::Basic(v),
            Version::Supports106(v) => Version::Supports106(v.into_static()),
            Version::Supports70001(v) => Version::Supports70001(v.into_static()),
        }
    }
}

impl<'a> Transcode<'a> for Version<'a> {
    fn parse<IResultErrT: ParseError<'a>>(
        input: &'a [u8],
    ) -> nom::IResult<&'a [u8], Self, IResultErrT> {
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
            Version::Basic(v) => v.deparsed_len(),
            Version::Supports106(v) => v.deparsed_len(),
            Version::Supports70001(v) => v.deparsed_len(),
        }
    }

    fn deparse(&self, output: &mut [u8]) {
        match self {
            Version::Basic(v) => v.deparse(output),
            Version::Supports106(v) => v.deparse(output),
            Version::Supports70001(v) => v.deparse(output),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, zerocopy::FromBytes)]
#[repr(C)]
pub struct Frame<BodyT> {
    pub header: Header,
    pub body: BodyT,
}

impl<'a, BodyT> Transcode<'a> for Frame<BodyT>
where
    BodyT: Transcode<'a>,
{
    /// Does *not* validate checksum or length - actual frame chunking is not our responsibility
    fn parse<IResultErrT: ParseError<'a>>(
        input: &'a [u8],
    ) -> nom::IResult<&'a [u8], Self, IResultErrT> {
        let (rest, header) = Header::parse(input)?;
        let (rest, body) = BodyT::parse(rest)?;
        Ok((rest, Frame { header, body }))
    }

    fn deparsed_len(&self) -> usize {
        self.header.deparsed_len() + self.body.deparsed_len()
    }

    /// Does *not* set checksum or length
    /// # Panics
    /// if `output.len() < self.deparsed_len()`
    fn deparse(&self, output: &mut [u8]) {
        let output = self.header.deparse_into_and_advance(output);
        self.body.deparse_into_and_advance(output);
    }
}

impl<'a, BodyT> Frame<BodyT>
where
    BodyT: Transcode<'a>,
{
    /// Sets checksum and length on self and in the buffer
    /// # Panics
    /// - if `output.len() < self.deparsed_len()`
    /// - if `self.body.deparsed_len() > u32::MAX`
    pub fn deparse_valid(&mut self, output: &mut [u8]) {
        self.deparse(output);
        let checksum = <bitcoin_hashes::sha256d::Hash as bitcoin_hashes::Hash>::hash(
            &output[std::mem::size_of::<Header>()..],
        );
        self.header.checksum = [checksum[0], checksum[1], checksum[2], checksum[3]];
        self.header.length = self
            .body
            .deparsed_len()
            .try_conv::<u32>()
            .expect("frame body too large")
            .into();
        self.header.write_to_prefix(output);
    }

    /// Sets checksum and length on self and in the buffer
    /// # Panics
    /// - if `self.body.deparsed_len() > u32::MAX`
    pub fn deparse_valid_to_vec(&mut self) -> Vec<u8> {
        let mut output = vec![0; self.deparsed_len()];
        self.deparse_valid(&mut output);
        output
    }

    /// Grows `output` to fit.
    /// Sets checksum and length on self and in the buffer
    /// # Panics
    /// - if `self.body.deparsed_len() > u32::MAX`
    pub(crate) fn deparse_valid_into(&mut self, output: &mut bytes::BytesMut) {
        output.resize(self.deparsed_len(), 0);
        self.deparse_valid(output)
    }
}

///////////////////////////////
// Primitive implementations //
///////////////////////////////

/// Transcode using [zerocopy::FromBytes]/[zerocopy::AsBytes]
macro_rules! transcode_primitive {
    ($($ty:ty $({ $array_len:ident })?),* $(,)?) => {
        $(
            #[automatically_derived]
            impl<'a $(, const $array_len: usize)?> Transcode<'a> for $ty {
                fn parse<IResultErrT: ParseError<'a>>(input: &'a [u8]) -> nom::IResult<&'a[u8], Self, IResultErrT> {
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

transcode_primitive!(U32le, U64le, U128netwk, U16netwk, I32le, I64le, [u8; N] { N }, ());

impl<'a> Transcode<'a> for bool {
    fn parse<IResultErrT: ParseError<'a>>(
        input: &'a [u8],
    ) -> nom::IResult<&'a [u8], Self, IResultErrT> {
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

///////////
// Utils //
///////////

/// Common constraint for [nom::IResult]'s error type.
/// This is a single place to add further errors, and allows us to compose parsing automatically
pub trait ParseError<'a>:
    nom::error::ParseError<&'a [u8]> + nom::error::FromExternalError<&'a [u8], std::str::Utf8Error>
{
}

impl<'a, T> ParseError<'a> for T where
    T: nom::error::ParseError<&'a [u8]>
        + nom::error::FromExternalError<&'a [u8], std::str::Utf8Error>
{
}

struct DebugWithDisplay<T>(T);

impl<T> fmt::Debug for DebugWithDisplay<T>
where
    T: fmt::Display,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!("{}", self.0))
    }
}

pub(crate) trait TranscodeExt<'a>: Transcode<'a> {
    fn deparse_into_and_advance<'output>(&self, output: &'output mut [u8]) -> &'output mut [u8] {
        self.deparse(output);
        &mut output[self.deparsed_len()..]
    }
    fn deparse_to_vec(&self) -> Vec<u8> {
        vec![0u8; self.deparsed_len()].tap_mut(|it| self.deparse(it))
    }
}

impl<'a, T> TranscodeExt<'a> for T where T: Transcode<'a> {}

#[cfg(test)]
mod transcoding {
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
        T: PartialEq + fmt::Debug + Transcode<'example>,
    {
        use pretty_assertions::assert_eq;

        let (_, parsed_bin) = T::parse::<nom::error::Error<_>>
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
                "35 8d 49 32",                         // - payload checksum (internal byte order)
            ]),
            Header {
                magic: crate::constants::Magic::Main.conv::<u32>().into(),
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
            VarStr::owned("/Satoshi:0.7.2/"),
        );
        do_test(&[0x00], VarStr::borrowed(""));
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
                    user_agent: VarStr::borrowed("/Satoshi:0.7.2/"),
                    start_height: 212672.into(),
                },
            }),
        );
    }

    #[test]
    fn version_with_header() {
        do_test(
            &hex2bin([
                // Message Header:
                "F9 BE B4 D9",                         //- Main network magic bytes
                "76 65 72 73 69 6F 6E 00 00 00 00 00", //- "version" command
                "64 00 00 00",                         //- Payload is 100 bytes long
                // BUG?(aatifsyed) I think this example from https://en.bitcoin.it/wiki/Protocol_documentation#version has the wrong checksum - see [checksum] test below
                "35 8d 49 32", // - payload checksum (internal byte order)
                // Version message:
                "62 EA 00 00",             // - 60002 (protocol version 60002)
                "01 00 00 00 00 00 00 00", // - 1 (NODE_NETWORK services)
                "11 B2 D0 50 00 00 00 00", // - Tue Dec 18 10:12:33 PST 2012
                "01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 FF FF 00 00 00 00 00 00", // - Recipient address info - see Network Address
                "01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 FF FF 00 00 00 00 00 00", // - Sender address info - see Network Address
                "3B 2E B3 5D 8C E6 17 65", // - Node ID
                "0F 2F 53 61 74 6F 73 68 69 3A 30 2E 37 2E 32 2F", // - "/Satoshi:0.7.2/" sub-version string (string is 15 bytes long)
                "C0 3E 03 00", // - Last block sending node has is block #212672
            ]),
            Frame {
                header: Header {
                    magic: crate::constants::Magic::Main.conv::<u32>().into(),
                    command: crate::constants::commands::arr::VERSION,
                    length: 100.into(),
                    checksum: [0x35, 0x8d, 0x49, 0x32],
                },
                body: Version106 {
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
                        user_agent: VarStr::borrowed("/Satoshi:0.7.2/"),
                        start_height: 212672.into(),
                    },
                },
            },
        )
    }

    /// bug in example at https://en.bitcoin.it/wiki/Protocol_documentation#version
    #[test]
    #[should_panic]
    fn test_checksum() {
        let bin = hex2bin([
            // Version message:
            "62 EA 00 00",             // - 60002 (protocol version 60002)
            "01 00 00 00 00 00 00 00", // - 1 (NODE_NETWORK services)
            "11 B2 D0 50 00 00 00 00", // - Tue Dec 18 10:12:33 PST 2012
            "01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 FF FF 00 00 00 00 00 00", // - Recipient address info - see Network Address
            "01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 FF FF 00 00 00 00 00 00", // - Sender address info - see Network Address
            "3B 2E B3 5D 8C E6 17 65",                         // - Node ID
            "0F 2F 53 61 74 6F 73 68 69 3A 30 2E 37 2E 32 2F", // - "/Satoshi:0.7.2/" sub-version string (string is 15 bytes long)
            "C0 3E 03 00", // - Last block sending node has is block #212672
        ]);
        let checksum = <bitcoin_hashes::sha256d::Hash as bitcoin_hashes::Hash>::hash(&bin);
        assert_eq!(
            [0x35, 0x8d, 0x49, 0x32], // from example
            [checksum[0], checksum[1], checksum[2], checksum[3]],
        )
    }

    #[test]
    fn verack() {
        do_test(
            &hex2bin([
                "F9 BE B4 D9",                          // - Main network magic bytes
                "76 65 72 61  63 6B 00 00 00 00 00 00", // - "verack" command
                "00 00 00 00",                          // - Payload is 0 bytes long
                "5D F6 E0 E2",                          // - Checksum (internal byte order)
            ]),
            Frame {
                header: Header {
                    magic: crate::constants::Magic::Main.conv::<u32>().into(),
                    command: crate::constants::commands::arr::VERACK,
                    length: 0.into(),
                    checksum: [0x5D, 0xF6, 0xE0, 0xE2],
                },
                body: (),
            },
        );
    }

    #[test]
    fn frame_checksum_and_len() {
        assert_eq!(
            hex2bin([
                "F9 BE B4 D9",                          // - Main network magic bytes
                "76 65 72 61  63 6B 00 00 00 00 00 00", // - "verack" command
                "00 00 00 00",                          // - Payload is 0 bytes long
                "5D F6 E0 E2",                          // - Checksum (internal byte order)
            ]),
            Frame {
                header: Header {
                    magic: crate::constants::Magic::Main.conv::<u32>().into(),
                    command: crate::constants::commands::arr::VERACK,
                    length: 0.into(),
                    checksum: [0; 4]
                },
                body: ()
            }
            .deparse_valid_to_vec()
        );
    }
}
