use std::{mem, net, str};

/// Attempt to deserialize this struct in accordance to the bitcoin protocol.
// The bitcoin protocol has variable-length fields, so we can't just use interpret structs with
// e.g [zerocopy::FromBytes]. Our implentation builds on [nom].
//
// Initial implementation used [nom_derive::Parse] trait, but the [nom_derive::Nom] derive macro
// is a little janky, and doesn't work if the struct definition is nested inside a declarative macro
// like [impl_parse_deparse_each_field].
//
// I didn't want to write a procedural macro just for that, so we use these two traits, and use the
// decl macro to implement for our business structs.
//
// The tradeoff here is losing the privilege of borrowing data from the serialized buffer, which can
// be an important performance optimisation, so this stands to be revisited.
//
// Another tradeoff is a lack of customisation at runtime and compile-time - Parse is per-type, and
// can't easily be tweaked, so all parsing differences need to be plumbed through types.
// As an example, suppose we wanted the following for security/trust considerations:
// ```rust
// struct BoundedString<const MAX_LEN: usize>(String);
// ```
// We now need to pollute all our types, and if we wanted to configure something like MAX_LEN at
// runtime, we'd have to create a parallel parse function like `parse_with_params`.
//
// I think a cutting-edge implementation has the following details:
// - Configurable serializers and deserializers, where security considerations, and tolerances for checksums,
//   and badly performing peers lives.
// - Serde-like zero-copy support. In rust's type system today (I think) this is impossible with a single
//   trait like [Parse] - it requires interaction between two traits. See the discussion at
//   https://users.rust-lang.org/t/implementation-is-not-general-enough/57433.
// - Separate structs for the wire representation, and the user-facing structs. This is necessary for some
//   of the above (like tolerating non-conforming peers) (this implementation muddles the two).
pub trait Parse: Sized /* TODO(aatifsyed): seal these traits */ {
    fn parse(buffer: &[u8]) -> nom::IResult<&[u8], Self>;
}

/// Serialize this struct in accordance to the bitcoin protocol.
// This trait and its implementors are broadly inspired by fuschia's netstack3 traits, which do a
// kind of inside-out packet parsing.
// See https://github.com/aatifsyed/fuschia-nestack-hacking.
// We are simpler by not having separate builder and parser structs, but a full-fat implementation
// would probably actually use those packet traits directly.
pub trait Deparse {
    /// The size of buffer required to deparse this struct (including all fields).
    /// MUST be equal to the number of bytes deparsed into `buffer` in [Deparse::deparse].
    fn deparsed_len(&self) -> usize;
    /// Deparse this struct into a buffer.
    /// Implementations may assume that `buffer.len() >= self.deparsed_len()`.
    fn deparse(&self, buffer: &mut [u8]);
}

/// Implement parse and deparse for this struct by parsing and deparsing each field in turn.
// bargain bucket derive macro
macro_rules! impl_parse_deparse_each_field {
    // Capture struct definition
    (
        $(#[$struct_meta:meta])*
        // TODO(aatifsyed): for zerocopy, we should handle generics and borrowed data here
        // (or just write a proc macro)
        $struct_vis:vis struct $struct_name:ident {
            $(
                $(#[$field_meta:meta])*
                $field_vis:vis $field_name:ident: $field_ty:ty,
            )*
        }
    ) => {
        // Passthrough the struct definition
        $(#[$struct_meta])*
        $struct_vis struct $struct_name {
            $(
                $(#[$field_meta])*
                $field_vis $field_name: $field_ty,
            )*
        }
        #[automatically_derived]
        impl $crate::Parse for $struct_name
        {
            fn parse(buffer: &[u8]) -> nom::IResult<& [u8], Self> {
                let rem = buffer;
                $( // parse each field in-order
                    let (rem, $field_name) = <$field_ty as $crate::Parse>::parse(rem)?;
                )*
                Ok((rem, Self {
                    $($field_name,)*
                }))
            }
        }
        #[automatically_derived]
        impl $crate::Deparse for $struct_name {
            fn deparsed_len(&self) -> usize {
                [
                    $(
                        <$field_ty as $crate::Deparse>::deparsed_len(&self.$field_name),
                    )*
                ].into_iter().sum()
            }
            fn deparse(&self, buffer: &mut [u8]) {
                $(
                    // deparse the field
                    <$field_ty as $crate::Deparse>::deparse(&self.$field_name, buffer);
                    // skip over the the now-deparsed bytes before deparsing the next field
                    let buffer = &mut buffer[<$field_ty as $crate::Deparse>::deparsed_len(&self.$field_name)..];
                )*
                let _ = buffer;
            }
        }
    };
}

impl_parse_deparse_each_field! {
/// Message header for all bitcoin protocol packets
// https://en.bitcoin.it/wiki/Protocol_documentation#Message_structure
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Header {
    /// Magic value indicating message origin network, and used to seek to next message when stream state is unknown
    pub magic: u32,
    /// ASCII string identifying the packet content, NULL padded (non-NULL padding results in packet rejected)
    pub command: [u8; 12],
    /// Length of payload in number of bytes
    pub length: u32,
    /// First 4 bytes of sha256(sha256(payload))
    pub checksum: [u8; 4],
}}

impl_parse_deparse_each_field! {
/// Fields present in all version packets
// https://en.bitcoin.it/wiki/Protocol_documentation#version
#[derive(Debug, Clone, PartialEq, Hash)]
pub struct VersionFieldsMandatory {
    /// Bitfield of features to be enabled for this connection.
    pub services: bitbag::BitBag<crate::constants::Services>,
    /// Standard UNIX timestamp in seconds.
    pub timestamp: chrono::NaiveDateTime,
    /// The network address of the node receiving this message.
    pub receiver: ServicesAndNetworkAddress,
}}

impl_parse_deparse_each_field! {
/// Fields present in all version packets at or after version 106
// https://en.bitcoin.it/wiki/Protocol_documentation#version
#[derive(Debug, Clone, PartialEq, Hash)]
pub struct VersionFields106 {
    /// Field can be ignored.
    /// This used to be the network address of the node emitting this message, but most P2P implementations send 26 dummy bytes.
    /// The "services" field of the address would also be redundant with the second field of the version message.
    pub sender: ServicesAndNetworkAddress,
    /// Node random nonce, randomly generated every time a version packet is sent. This nonce is used to detect connections to self.
    pub nonce: u64,
    /// User Agent (0x00 if string is 0 bytes long)
    pub user_agent: String,
    /// The last block received by the emitting node
    pub start_height: u32,
}}

impl_parse_deparse_each_field! {
/// Fields present in all version packets at or after version 70001
// https://en.bitcoin.it/wiki/Protocol_documentation#version
#[derive(Debug, Clone, PartialEq, Hash, )]
pub struct VersionFields70001 {
    /// Whether the remote peer should announce relayed transactions or not, see BIP 0037
    pub relay: bool,
}}

/// Copy bytes from `src` to `dst`.
fn frontfill(src: &[u8], dst: &mut [u8]) {
    for (src, dst) in src.iter().zip(dst) {
        *dst = *src
    }
}

impl Parse for String {
    /// # Security
    /// Defense against buffer over-allocations is a DoS concern in untrusted environments.
    /// Allocation is postponed until `buffer` has been read, so the owner of `buffer` (indirectly)
    /// controls tolerance against over-allocations.
    /// See discussion under the [Parse] trait for future improvments.
    fn parse(buffer: &[u8]) -> nom::IResult<&[u8], Self> {
        let (rem, length) = VarInt::parse(buffer)?;
        let (rem, s) = nom::combinator::map_res(
            // should fail to compile on 32-bit platforms, as nom::traits::ToUsize isn't implemented for u64 on those platforms
            // so we should be arithmetically safe
            nom::bytes::streaming::take(length.inner),
            str::from_utf8,
        )(rem)?;
        Ok((rem, String::from(s)))
    }
}

impl Deparse for String {
    fn deparsed_len(&self) -> usize {
        VarInt::from(self.len()).deparsed_len() + self.len()
    }

    fn deparse(&self, buffer: &mut [u8]) {
        let len = VarInt::from(self.len());
        len.deparse(buffer);
        frontfill(self.as_bytes(), &mut buffer[len.deparsed_len()..]);
    }
}

/// A bitcoin protocol message
#[derive(Debug, Clone, PartialEq, Hash)]
pub struct Message {
    /// The network that this message is for.
    pub magic: u32,
    pub body: MessageBody,
}
impl Message {
    pub fn known_magic(&self) -> Option<crate::constants::Magic> {
        crate::constants::Magic::try_from(self.magic).ok()
    }
}

#[derive(Debug, Clone, PartialEq, Hash)]
pub enum MessageBody {
    Version(Version),
    Verack,
}

impl MessageBody {
    fn command(&self) -> [u8; 12] {
        match self {
            MessageBody::Version(_) => crate::constants::commands::VERSION,
            MessageBody::Verack => crate::constants::commands::VERACK,
        }
    }
}

impl Parse for Message {
    fn parse(buffer: &[u8]) -> nom::IResult<&[u8], Self> {
        let (rem, header) = Header::parse(buffer)?;
        let (rem_packet, body) = nom::bytes::streaming::take(header.length)(rem)?;
        match header.command {
            crate::constants::commands::VERSION => {
                let (rem_body, version) = Version::parse(body)?;
                if !rem_body.is_empty() {
                    // TODO(aatifsyed) configurable tolerance for packet being oversized
                }
                Ok((
                    rem_packet,
                    Message {
                        magic: header.magic,
                        body: MessageBody::Version(version),
                    },
                ))
            }
            crate::constants::commands::VERACK => {
                if !header.length == 0 {
                    // TODO(aatifsyed) configurable tolerance for packet being oversized
                }
                Ok((
                    rem_packet,
                    Message {
                        magic: header.magic,
                        body: MessageBody::Verack,
                    },
                ))
            }
            // TODO(aatifsyed) plumb the errors here properly
            // [Parse] should be generic over the error type, and allow adding context to errors
            // like "unknown command string"
            _ => Err(nom::Err::Failure(nom::error::Error::new(
                buffer,
                nom::error::ErrorKind::Fail,
            ))),
        }
    }
}

impl Deparse for Message {
    fn deparsed_len(&self) -> usize {
        mem::size_of::<Header>()
            + match &self.body {
                MessageBody::Version(version) => version.deparsed_len(),
                MessageBody::Verack => 0,
            }
    }

    fn deparse(&self, buffer: &mut [u8]) {
        let (length, checksum) = match &self.body {
            MessageBody::Version(version) => {
                let body = &mut buffer[mem::size_of::<Header>()..];
                version.deparse(body);
                let checksum = <bitcoin_hashes::sha256d::Hash as bitcoin_hashes::Hash>::hash(body);
                (
                    version.deparsed_len(),
                    [checksum[0], checksum[1], checksum[2], checksum[3]],
                )
            }
            MessageBody::Verack => (0, [0; 4]),
        };
        let header = Header {
            magic: self.magic,
            command: self.body.command(),
            length: length as _,
            checksum,
        };
        header.deparse(buffer)
    }
}

// This implementation muddles wire representations, and application representations - future iterations
// should separate these concepts:
// ```rust
// mod wire {
//     struct Foo {
//         timestamp: u64
//     }
// }
// struct Foo {
//     timestamp: chrono::NaiveDateTime
// }
// impl From<wire::Foo> for Foo {..}
// ```
impl Parse for chrono::NaiveDateTime {
    fn parse(buffer: &[u8]) -> nom::IResult<&[u8], Self> {
        let (rem, timestamp) = nom::combinator::map_res(u64::parse, i64::try_from)(buffer)?;
        let timestamp =
            chrono::NaiveDateTime::from_timestamp_opt(timestamp, 0).ok_or_else(|| {
                nom::Err::Error(nom::error::make_error(
                    buffer,
                    nom::error::ErrorKind::MapOpt,
                ))
            })?;
        Ok((rem, timestamp))
    }
}

impl Deparse for chrono::NaiveDateTime {
    fn deparsed_len(&self) -> usize {
        mem::size_of::<i64>()
    }

    fn deparse(&self, buffer: &mut [u8]) {
        frontfill(&self.timestamp().to_le_bytes(), buffer)
    }
}

/// Protocol version `..106`.
type VersionBasic = clamped::ClampedI32To<106>;

/// Protocol version `106..70001`.
type Version106 = clamped::ClampedI32<106, 70001>;

/// Protocol version `70001..`.
type Version70001 = clamped::ClampedI32From<70001>;

/// A version advertisement.
/// Progressive versions added more fields, which can be accessed based on enum variant.
// Illegal states (mismatched version numbers) are unrepresentable.
#[derive(Debug, Clone, PartialEq, Hash)]
pub enum Version {
    Basic {
        version: VersionBasic,
        fields: VersionFieldsMandatory,
    },
    Supports106 {
        version: Version106,
        fields: VersionFieldsMandatory,
        fields_106: VersionFields106,
    },
    Supports70001 {
        version: Version70001,
        fields: VersionFieldsMandatory,
        fields_106: VersionFields106,
        fields_70001: VersionFields70001,
    },
}

impl Parse for Version {
    fn parse(buffer: &[u8]) -> nom::IResult<&[u8], Self> {
        let (rem, version) = i32::parse(buffer)?;
        match version {
            ..=105 => {
                let version =
                    clamped::ClampedI32To::try_from(version).expect("already checked clamp");
                let (rem, fields) = VersionFieldsMandatory::parse(rem)?;
                Ok((rem, Self::Basic { version, fields }))
            }
            106..=70000 => {
                let version =
                    clamped::ClampedI32::try_from(version).expect("already checked clamp");
                let (rem, fields) = VersionFieldsMandatory::parse(rem)?;
                let (rem, fields_106) = VersionFields106::parse(rem)?;
                Ok((
                    rem,
                    Self::Supports106 {
                        version,
                        fields,
                        fields_106,
                    },
                ))
            }
            70001.. => {
                let version =
                    clamped::ClampedI32From::try_from(version).expect("already checked clamp");
                let (rem, fields) = VersionFieldsMandatory::parse(rem)?;
                let (rem, fields_106) = VersionFields106::parse(rem)?;
                let (rem, fields_70001) = VersionFields70001::parse(rem)?;
                Ok((
                    rem,
                    Self::Supports70001 {
                        version,
                        fields,
                        fields_106,
                        fields_70001,
                    },
                ))
            }
        }
    }
}

impl Deparse for Version {
    fn deparsed_len(&self) -> usize {
        let mut len = self.version().deparsed_len() + self.fields().deparsed_len();
        if let Some(fields_106) = self.fields_106() {
            len += fields_106.deparsed_len();
            if let Some(fields_70001) = self.fields_70001() {
                len += fields_70001.deparsed_len()
            }
        }
        len
    }

    fn deparse(&self, buffer: &mut [u8]) {
        self.version().deparse(buffer);
        let buffer = &mut buffer[self.version().deparsed_len()..];
        self.fields().deparse(buffer);
        let buffer = &mut buffer[self.fields().deparsed_len()..];
        if let Some(fields_106) = self.fields_106() {
            fields_106.deparse(buffer);
            let buffer = &mut buffer[fields_106.deparsed_len()..];
            if let Some(fields_70001) = self.fields_70001() {
                fields_70001.deparse(buffer)
            }
        }
    }
}

impl Version {
    pub fn version(&self) -> i32 {
        match self {
            Version::Basic { version, .. } => (*version).into(),
            Version::Supports106 { version, .. } => (*version).into(),
            Version::Supports70001 { version, .. } => (*version).into(),
        }
    }
    pub fn fields(&self) -> &VersionFieldsMandatory {
        match self {
            Version::Basic { fields, .. } => fields,
            Version::Supports106 { fields, .. } => fields,
            Version::Supports70001 { fields, .. } => fields,
        }
    }
    pub fn fields_106(&self) -> Option<&VersionFields106> {
        match self {
            Version::Basic { .. } => None,
            Version::Supports106 { fields_106, .. } => Some(fields_106),
            Version::Supports70001 { fields_106, .. } => Some(fields_106),
        }
    }
    pub fn fields_70001(&self) -> Option<&VersionFields70001> {
        match self {
            Version::Basic { .. } => None,
            Version::Supports106 { .. } => None,
            Version::Supports70001 { fields_70001, .. } => Some(fields_70001),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VarInt {
    pub inner: u64,
}

#[cfg(target_pointer_width = "64")]
impl From<usize> for VarInt {
    fn from(value: usize) -> Self {
        Self { inner: value as _ }
    }
}

impl Parse for VarInt {
    fn parse(buffer: &[u8]) -> nom::IResult<&[u8], Self> {
        use tap::Pipe as _;
        let (rem, inner) = {
            let (rem, first_byte) = u8::parse(buffer)?;
            match first_byte {
                // 0xFF followed by the length as uint64_t
                0xFF => u64::parse(rem)?,
                // 0xFE followed by the length as uint32_t
                0xFE => u32::parse(rem)?.pipe(|(rem, i)| (rem, i as u64)),
                // 0xFD followed by the length as uint16_t
                0xFD => u16::parse(rem)?.pipe(|(rem, i)| (rem, i as u64)),
                i => (rem, i.into()),
            }
        };
        Ok((rem, Self { inner }))
    }
}

impl Deparse for VarInt {
    fn deparsed_len(&self) -> usize {
        // a more direct translation of protocol documentation
        #[allow(clippy::match_overlapping_arm)]
        match self.inner {
            ..=0xFE => 1,
            ..=0xFFFF => 3,
            ..=0xFFFF_FFFF => 5,
            _ => 9,
        }
    }

    fn deparse(&self, buffer: &mut [u8]) {
        match self.inner {
            small @ ..=0xFE => buffer[0] = small as u8,
            medium @ ..=0xFFFF => {
                buffer[0] = 0xFD;
                frontfill(&u16::to_le_bytes(medium as _), &mut buffer[1..])
            }
            large @ ..=0xFFFF_FFFF => {
                buffer[0] = 0xFE;
                frontfill(&u32::to_le_bytes(large as _), &mut buffer[1..])
            }
            xlarge => {
                buffer[0] = 0xFF;
                frontfill(&u64::to_le_bytes(xlarge as _), &mut buffer[1..])
            }
        }
    }
}

////////////////////////////////////////////////
// These implementations are less interesting //
////////////////////////////////////////////////

/// Plain integers are little-endian encoded.
macro_rules! impl_parse_deparse_via_le_bytes {
    ($($nom_parser:path => $ty:ty),* $(,)?) => {
        $(
            impl $crate::Parse for $ty {
                fn parse(buffer: &[u8]) -> nom::IResult<& [u8], Self> {
                    $nom_parser(buffer)
                }
            }
            impl $crate::Deparse for $ty {
                fn deparsed_len(&self) -> usize {
                    mem::size_of::<Self>()
                }

                fn deparse(&self, buffer: &mut [u8]) {
                    frontfill(&self.to_le_bytes(), buffer)
                }
            }
        )*
    };
}

impl_parse_deparse_via_le_bytes!(
    nom::number::streaming::le_u8 => u8,
    nom::number::streaming::le_u16 => u16,
    nom::number::streaming::le_i32 => i32,
    nom::number::streaming::le_u32 => u32,
    nom::number::streaming::le_i64 => i64,
    nom::number::streaming::le_u64 => u64,
);

impl<const N: usize, T> Parse for [T; N]
where
    T: Parse,
{
    fn parse(buffer: &[u8]) -> nom::IResult<&[u8], Self> {
        use nom::{
            combinator::{complete, map_res},
            multi::many_m_n,
        };
        map_res(many_m_n(N, N, complete(<T>::parse)), Self::try_from)(buffer)
    }
}

impl<const N: usize> Deparse for [u8; N] {
    fn deparsed_len(&self) -> usize {
        mem::size_of::<Self>()
    }

    fn deparse(&self, buffer: &mut [u8]) {
        use zerocopy::AsBytes; // TODO(aatifsyed) can we just use nom::AsBytes?
        frontfill(self.as_bytes(), buffer)
    }
}

impl<T> Parse for bitbag::BitBag<T>
where
    T: bitbag::BitBaggable,
    T::Repr: Parse,
{
    fn parse(buffer: &[u8]) -> nom::IResult<&[u8], Self> {
        T::Repr::parse(buffer).map(|(rem, repr)| (rem, bitbag::BitBag::new_unchecked(repr)))
    }
}

impl<T> Deparse for bitbag::BitBag<T>
where
    T: bitbag::BitBaggable,
    T::Repr: Deparse,
{
    fn deparsed_len(&self) -> usize {
        self.inner().deparsed_len()
    }

    fn deparse(&self, buffer: &mut [u8]) {
        self.inner().deparse(buffer)
    }
}

impl Parse for bool {
    fn parse(buffer: &[u8]) -> nom::IResult<&[u8], Self> {
        let (rem, byte) = u8::parse(buffer)?;
        match byte {
            1 => Ok((rem, true)),
            0 => Ok((rem, false)),
            // TODO(aatifsyed): "forbidden layout for bool"
            _ => Err(nom::Err::Error(nom::error::Error::new(
                buffer,
                nom::error::ErrorKind::Alt,
            ))),
        }
    }
}

impl Deparse for bool {
    fn deparsed_len(&self) -> usize {
        1
    }

    fn deparse(&self, buffer: &mut [u8]) {
        match self {
            true => buffer[0] = 1,
            false => buffer[0] = 0,
        }
    }
}

// https://en.bitcoin.it/wiki/Protocol_documentation#Network_address
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ServicesAndNetworkAddress {
    /// same service(s) listed in version.
    pub services: bitbag::BitBag<crate::constants::Services>,
    /// IPv6 address. Network byte order. The original client only supported IPv4 and only read the last 4 bytes to get the IPv4 address. However, the IPv4 address is written into the message as a 16 byte IPv4-mapped IPv6 address
    /// (12 bytes 00 00 00 00 00 00 00 00 00 00 FF FF, followed by the 4 bytes of the IPv4 address).
    pub ipv6: net::Ipv6Addr,
    /// port number, network byte order
    pub port: u16,
}

impl Parse for ServicesAndNetworkAddress {
    fn parse(buffer: &[u8]) -> nom::IResult<&[u8], Self> {
        let (rem, services) = Parse::parse(buffer)?;
        let (rem, ipv6) = nom::number::streaming::be_u128(rem)?;
        let (rem, port) = nom::number::streaming::be_u16(rem)?;
        Ok((
            rem,
            Self {
                services,
                ipv6: ipv6.into(),
                port,
            },
        ))
    }
}

impl Deparse for ServicesAndNetworkAddress {
    fn deparsed_len(&self) -> usize {
        self.services.deparsed_len() + mem::size_of::<u128>() + mem::size_of::<u16>()
    }

    fn deparse(&self, buffer: &mut [u8]) {
        let buffer = &mut buffer[0..];
        self.services.deparse(buffer);
        let buffer = &mut buffer[self.services.deparsed_len()..];
        frontfill(&u128::from(self.ipv6).to_be_bytes(), buffer);
        let buffer = &mut buffer[mem::size_of::<u128>()..];
        frontfill(&self.port.to_be_bytes(), buffer);
    }
}

macro_rules! impl_for_clamped {
    () => {
        fn deparsed_len(&self) -> usize {
            mem::size_of::<i32>()
        }

        fn deparse(&self, buffer: &mut [u8]) {
            i32::from(*self).deparse(buffer)
        }
    };
}

impl<const UPPER: i32> Deparse for clamped::ClampedI32To<UPPER> {
    impl_for_clamped!();
}
impl<const LOWER: i32, const UPPER: i32> Deparse for clamped::ClampedI32<LOWER, UPPER> {
    impl_for_clamped!();
}
impl<const UPPER: i32> Deparse for clamped::ClampedI32From<UPPER> {
    impl_for_clamped!();
}

pub mod constants {
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

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, num_enum::TryFromPrimitive)]
    #[repr(u32)]
    pub enum Magic {
        Main = 0xD9B4BEF9,
        Testnet = 0xDAB5BFFA,
        Testnet3 = 0x0709110B,
        Signet = 0x40CF030A,
        Namecoin = 0xFEB4BEF9,
    }

    /// Allow [MessageBody::command] and [Message::parse] to use the same arrays
    pub(crate) mod commands {
        pub const VERSION: [u8; 12] = *b"version\0\0\0\0\0";
        pub const VERACK: [u8; 12] = *b"verack\0\0\0\0\0\0";
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt;

    fn hex2bin<'a>(hex: impl IntoIterator<Item = &'a str>) -> Vec<u8> {
        use tap::Pipe;
        hex.into_iter()
            .flat_map(str::chars)
            .filter(char::is_ascii_alphanumeric)
            .collect::<String>()
            .pipe(hex::decode)
            .expect("example is not valid hex")
    }

    fn do_test<'a, T>(example_bin: impl IntoIterator<Item = &'a str>, expected: T)
    where
        T: Parse + Deparse + PartialEq + fmt::Debug,
    {
        use pretty_assertions::assert_eq;

        let example_bin = hex2bin(example_bin);

        let (leftover, parsed_bin) =
            T::parse(example_bin.as_slice()).expect("parsing the example text failed");
        assert_eq!(leftover.len(), 0, "example text wasn't fully parsed");
        assert_eq!(
            expected, parsed_bin,
            "the parsed example text doesn't match the expected struct"
        );

        let mut unparsed_bin = vec![0u8; expected.deparsed_len()];
        expected.deparse(&mut unparsed_bin);
        assert_eq!(
            example_bin, unparsed_bin,
            "the unparsed struct doesn't match the example bin"
        );
    }

    #[test]
    fn test_header() {
        do_test(
            [
                "F9 BE B4 D9",                         // - Main network magic bytes
                "76 65 72 73 69 6F 6E 00 00 00 00 00", // - "version" command
                "64 00 00 00",                         // - Payload is 100 bytes long
                "35 8d 49 32",                         // - payload checksum (internal byte order)
            ],
            Header {
                magic: crate::constants::Magic::Main as u32,
                command: *b"version\0\0\0\0\0",
                length: 100,
                checksum: [0x35, 0x8d, 0x49, 0x32],
            },
        )
    }

    #[test]
    fn test_string() {
        do_test(
            ["0F 2F 53 61 74 6F 73 68 69 3A 30 2E 37 2E 32 2F"],
            String::from("/Satoshi:0.7.2/"),
        );
        do_test(["00"], String::from(""));
    }

    #[test]
    fn test_version_body() {
        do_test(
            [
                "62 EA 00 00",             // - 60002 (protocol version 60002)
                "01 00 00 00 00 00 00 00", // - 1 (NODE_NETWORK services)
                "11 B2 D0 50 00 00 00 00", // - Tue Dec 18 10:12:33 PST 2012
                "01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 FF FF 00 00 00 00 00 00", // - Recipient address info - see Network Address
                "01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 FF FF 00 00 00 00 00 00", // - Sender address info - see Network Address
                "3B 2E B3 5D 8C E6 17 65", // - Node ID
                "0F 2F 53 61 74 6F 73 68 69 3A 30 2E 37 2E 32 2F", // - "/Satoshi:0.7.2/" sub-version string (string is 15 bytes long)
                "C0 3E 03 00", // - Last block sending node has is block #212672
            ],
            Version::Supports106 {
                version: 60002.try_into().unwrap(),
                fields: VersionFieldsMandatory {
                    services: crate::constants::Services::NodeNetwork.into(),
                    timestamp: "2012-12-18T18:12:33".parse().unwrap(),
                    receiver: ServicesAndNetworkAddress {
                        services: crate::constants::Services::NodeNetwork.into(),
                        ipv6: net::Ipv4Addr::UNSPECIFIED.to_ipv6_mapped(),
                        port: 0,
                    },
                },
                fields_106: VersionFields106 {
                    sender: ServicesAndNetworkAddress {
                        services: crate::constants::Services::NodeNetwork.into(),
                        ipv6: net::Ipv4Addr::UNSPECIFIED.to_ipv6_mapped(),
                        port: 0,
                    },
                    nonce: 7284544412836900411,
                    user_agent: String::from("/Satoshi:0.7.2/"),
                    start_height: 212672,
                },
            },
        );
    }

    #[test]
    fn test_version_with_header() {
        do_test(
            [
                // Message Header:
                "F9 BE B4 D9",                         //- Main network magic bytes
                "76 65 72 73 69 6F 6E 00 00 00 00 00", //- "version" command
                "64 00 00 00",                         //- Payload is 100 bytes long
                // BUG?(aatifsyed) I think the example from https://en.bitcoin.it/wiki/Protocol_documentation#version has the wrong checksum
                // See below
                // "35 8d 49 32", // - payload checksum (internal byte order)
                "3b 64 8d 5a", //-  payload checksum (internal byte order)
                // Version message:
                "62 EA 00 00",             // - 60002 (protocol version 60002)
                "01 00 00 00 00 00 00 00", // - 1 (NODE_NETWORK services)
                "11 B2 D0 50 00 00 00 00", // - Tue Dec 18 10:12:33 PST 2012
                "01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 FF FF 00 00 00 00 00 00", // - Recipient address info - see Network Address
                "01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 FF FF 00 00 00 00 00 00", // - Sender address info - see Network Address
                "3B 2E B3 5D 8C E6 17 65", // - Node ID
                "0F 2F 53 61 74 6F 73 68 69 3A 30 2E 37 2E 32 2F", // - "/Satoshi:0.7.2/" sub-version string (string is 15 bytes long)
                "C0 3E 03 00", // - Last block sending node has is block #212672
            ],
            Message {
                magic: crate::constants::Magic::Main as _,
                body: MessageBody::Version(Version::Supports106 {
                    version: 60002.try_into().unwrap(),
                    fields: VersionFieldsMandatory {
                        services: crate::constants::Services::NodeNetwork.into(),
                        timestamp: "2012-12-18T18:12:33".parse().unwrap(),
                        receiver: ServicesAndNetworkAddress {
                            services: crate::constants::Services::NodeNetwork.into(),
                            ipv6: std::net::Ipv4Addr::UNSPECIFIED.to_ipv6_mapped(),
                            port: 0,
                        },
                    },
                    fields_106: VersionFields106 {
                        sender: ServicesAndNetworkAddress {
                            services: crate::constants::Services::NodeNetwork.into(),
                            ipv6: std::net::Ipv4Addr::UNSPECIFIED.to_ipv6_mapped(),
                            port: 0,
                        },
                        nonce: 7284544412836900411,
                        user_agent: String::from("/Satoshi:0.7.2/"),
                        start_height: 212672,
                    },
                }),
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
}
