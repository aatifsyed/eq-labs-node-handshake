// Initial implementation used [nom_derive::Parse] trait, but the [nom_derive::Nom] derive macro
// is a little janky, and doesn't work if the struct definition is nested inside a declarative macro
// like [impl_parse_deparse_each_field].
// I didn't want to write a procedural macro just for that, so we use these two traits, and use the
// decl macro to implement for our business structs.
pub trait Parse: Sized {
    fn parse<'a>(buffer: &'a [u8]) -> nom::IResult<&'a [u8], Self>;
}

pub trait ParseOwned: for<'a> Parse {}
impl<T: for<'a> Parse> ParseOwned for T {}

pub trait Deparse {
    /// The size of buffer required to deparse this struct (including all fields)
    fn deparsed_len(&self) -> usize;
    /// Deparse this struct into a buffer
    fn deparse(&self, buffer: &mut [u8]);
}

// bargain bucket derive macro
macro_rules! impl_parse_deparse_each_field {
    (
        $(#[$struct_meta:meta])*
        $struct_vis:vis struct $struct_name:ident {
            $(
                $(#[$field_meta:meta])*
                $field_vis:vis $field_name:ident: $field_ty:ty,
            )*
        }
    ) => {
        $(#[$struct_meta])*
        $struct_vis struct $struct_name {
            $(
                $(#[$field_meta])*
                $field_vis $field_name: $field_ty,
            )*
        }
        impl $crate::Parse for $struct_name
        {
            fn parse<'a>(buffer: &'a [u8]) -> nom::IResult<&'a [u8], Self> {
                let rem = buffer;
                $(
                    let (rem, $field_name) = <$field_ty as $crate::Parse>::parse(rem)?;
                )*
                Ok((rem, Self {
                    $(
                        $field_name,
                    )*
                }))
            }
        }
        impl $crate::Deparse for $struct_name {
            fn deparsed_len(&self) -> usize {
                [
                    $(
                        <$field_ty as $crate::Deparse>::deparsed_len(&self.$field_name),
                    )*
                ].into_iter().sum()
            }
            fn deparse(&self, buffer: &mut [u8]) {
                let buffer = &mut buffer[0..];
                $(
                    <$field_ty as $crate::Deparse>::deparse(&self.$field_name, buffer);
                    let buffer = &mut buffer[<$field_ty as $crate::Deparse>::deparsed_len(&self.$field_name)..];
                )*
                let _ = buffer;
            }
        }
    };
}

impl_parse_deparse_each_field!(
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    #[repr(C)]
    pub struct Header {
        /// Magic value indicating message origin network, and used to seek to next message when stream state is unknown
        pub magic: u32,
        /// ASCII string identifying the packet content, NULL padded (non-NULL padding results in packet rejected)
        pub command: [u8; 12],
        /// Length of payload in number of bytes
        pub length: u32,
        /// First 4 bytes of sha256(sha256(payload))
        pub checksum: [u8; 4],
    }
);

macro_rules! impl_parse_deparse_via_le_bytes {
    ($($nom_parser:path => $ty:ty),* $(,)?) => {
        $(
            impl $crate::Parse for $ty {
                fn parse<'a>(buffer: &'a [u8]) -> nom::IResult<&'a [u8], Self> {
                    $nom_parser(buffer)
                }
            }
            impl $crate::Deparse for $ty {
                fn deparsed_len(&self) -> usize {
                    std::mem::size_of::<Self>()
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
    fn parse<'a>(buffer: &'a [u8]) -> nom::IResult<&'a [u8], Self> {
        use nom::{
            combinator::{complete, map_res},
            multi::many_m_n,
        };
        map_res(many_m_n(N, N, complete(<T>::parse)), Self::try_from)(buffer)
    }
}

impl<const N: usize> Deparse for [u8; N] {
    fn deparsed_len(&self) -> usize {
        std::mem::size_of::<Self>()
    }

    fn deparse(&self, buffer: &mut [u8]) {
        use zerocopy::AsBytes; // TODO(aatifsyed) can we just use nom::AsBytes?
        frontfill(self.as_bytes(), buffer)
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
    fn parse<'a>(buffer: &'a [u8]) -> nom::IResult<&'a [u8], Self> {
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

impl Parse for String {
    fn parse<'a>(buffer: &'a [u8]) -> nom::IResult<&'a [u8], Self> {
        let (rem, length) = VarInt::parse(buffer)?;
        let (rem, s) = nom::combinator::map_res(
            // should fail to compile on 32-bit platforms, as nom::traits::ToUsize isn't implemented for u64 on those platforms
            // so we should be arithmetically safe
            nom::bytes::streaming::take(length.inner),
            std::str::from_utf8,
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

impl<T> Parse for bitbag::BitBag<T>
where
    T: bitbag::BitBaggable,
    T::Repr: Parse,
{
    fn parse<'a>(buffer: &'a [u8]) -> nom::IResult<&'a [u8], Self> {
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

impl Parse for chrono::NaiveDateTime {
    fn parse<'a>(buffer: &'a [u8]) -> nom::IResult<&'a [u8], Self> {
        let (rem, timestamp) = nom::combinator::map_res(u64::parse, i64::try_from)(buffer)?;
        let timestamp = chrono::NaiveDateTime::from_timestamp_opt(timestamp.into(), 0).ok_or(
            nom::Err::Error(nom::error::make_error(
                buffer,
                nom::error::ErrorKind::MapOpt,
            )),
        )?;
        Ok((rem, timestamp))
    }
}

impl Deparse for chrono::NaiveDateTime {
    fn deparsed_len(&self) -> usize {
        std::mem::size_of::<i64>()
    }

    fn deparse(&self, buffer: &mut [u8]) {
        frontfill(&self.timestamp().to_le_bytes(), buffer)
    }
}

impl Parse for bool {
    fn parse<'a>(buffer: &'a [u8]) -> nom::IResult<&'a [u8], Self> {
        let (rem, byte) = u8::parse(buffer)?;
        match byte {
            1 => Ok((rem, true)),
            0 => Ok((rem, false)),
            // TODO(aatifsyed) plumb the errors here properly
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NetworkAddressWithoutTime {
    pub services: bitbag::BitBag<crate::constants::Services>,
    pub ipv6: std::net::Ipv6Addr,
    pub port: u16,
}

impl Parse for NetworkAddressWithoutTime {
    fn parse<'a>(buffer: &'a [u8]) -> nom::IResult<&'a [u8], Self> {
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

fn frontfill(src: &[u8], dst: &mut [u8]) {
    for (src, dst) in src.iter().zip(dst) {
        *dst = *src
    }
}

impl Deparse for NetworkAddressWithoutTime {
    fn deparsed_len(&self) -> usize {
        self.services.deparsed_len() + std::mem::size_of::<u128>() + std::mem::size_of::<u16>()
    }

    fn deparse(&self, buffer: &mut [u8]) {
        let buffer = &mut buffer[0..];
        self.services.deparse(buffer);
        let buffer = &mut buffer[self.services.deparsed_len()..];
        frontfill(&u128::from(self.ipv6).to_be_bytes(), buffer);
        let buffer = &mut buffer[std::mem::size_of::<u128>()..];
        frontfill(&self.port.to_be_bytes(), buffer);
    }
}

#[derive(Debug, Clone, PartialEq, Hash)]
pub struct Message {
    pub magic: u32,
    pub body: MessageBody,
}

#[derive(Debug, Clone, PartialEq, Hash)]
pub enum MessageBody {
    Version(Version),
    Verack,
}

impl MessageBody {
    fn command(&self) -> [u8; 12] {
        match self {
            MessageBody::Version(_) => *b"version\0\0\0\0\0",
            MessageBody::Verack => *b"verack\0\0\0\0\0\0",
        }
    }
}

impl Parse for Message {
    fn parse<'a>(buffer: &'a [u8]) -> nom::IResult<&'a [u8], Self> {
        let (rem, header) = Header::parse(buffer)?;
        let (rem_packet, body) = nom::bytes::streaming::take(header.length)(rem)?;
        match &header.command {
            b"version\0\0\0\0\0" => {
                let (rem_body, version) = Version::parse(body)?;
                if !rem_body.is_empty() {
                    // ?
                }
                Ok((
                    rem_packet,
                    Message {
                        magic: header.magic,
                        body: MessageBody::Version(version),
                    },
                ))
            }
            b"verack\0\0\0\0\0\0" => {
                if !header.length == 0 {
                    todo!()
                }
                Ok((
                    rem_packet,
                    Message {
                        magic: header.magic,
                        body: MessageBody::Verack,
                    },
                ))
            }
            _ => todo!(),
        }
    }
}

impl Deparse for Message {
    fn deparsed_len(&self) -> usize {
        std::mem::size_of::<Header>()
            + match &self.body {
                MessageBody::Version(version) => version.deparsed_len(),
                MessageBody::Verack => 0,
            }
    }

    fn deparse(&self, buffer: &mut [u8]) {
        let (length, checksum) = match &self.body {
            MessageBody::Version(version) => {
                let body = &mut buffer[std::mem::size_of::<Header>()..];
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

macro_rules! impl_for_clamped {
    () => {
        fn deparsed_len(&self) -> usize {
            std::mem::size_of::<u32>()
        }

        fn deparse(&self, buffer: &mut [u8]) {
            u32::from(*self).deparse(buffer)
        }
    };
}

impl<const UPPER: u32> Deparse for clamped::ClampedU32To<UPPER> {
    impl_for_clamped!();
}
impl<const LOWER: u32, const UPPER: u32> Deparse for clamped::ClampedU32<LOWER, UPPER> {
    impl_for_clamped!();
}
impl<const UPPER: u32> Deparse for clamped::ClampedU32From<UPPER> {
    impl_for_clamped!();
}

/// Protocol version `..106`.
type VersionBasic = clamped::ClampedU32To<106>;

/// Protocol version `106..70001`.
type Version106 = clamped::ClampedU32<106, 70001>;

/// Protocol version `70001..`.
type Version70001 = clamped::ClampedU32From<70001>;

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
    fn parse<'a>(buffer: &'a [u8]) -> nom::IResult<&'a [u8], Self> {
        let (rem, version) = u32::parse(buffer)?;
        match version {
            ..=105 => {
                let version =
                    clamped::ClampedU32To::try_from(version).expect("already checked length");
                let (rem, fields) = VersionFieldsMandatory::parse(rem)?;
                Ok((rem, Self::Basic { version, fields }))
            }
            106..=70000 => {
                let version =
                    clamped::ClampedU32::try_from(version).expect("already checked length");
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
                    clamped::ClampedU32From::try_from(version).expect("already checked length");
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
    pub fn version(&self) -> u32 {
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

impl_parse_deparse_each_field! {
// https://en.bitcoin.it/wiki/Protocol_documentation#version
#[derive(Debug, Clone, PartialEq, Hash)]
pub struct VersionFieldsMandatory {
    /// Bitfield of features to be enabled for this connection.
    pub services: bitbag::BitBag<crate::constants::Services>,
    /// Standard UNIX timestamp in seconds.
    pub timestamp: chrono::NaiveDateTime,
    /// The network address of the node receiving this message.
    pub receiver: NetworkAddressWithoutTime,
}}

impl_parse_deparse_each_field! {
    // https://en.bitcoin.it/wiki/Protocol_documentation#version
#[derive(Debug, Clone, PartialEq, Hash)]
pub struct VersionFields106 {
    /// Field can be ignored.
    /// This used to be the network address of the node emitting this message, but most P2P implementations send 26 dummy bytes.
    /// The "services" field of the address would also be redundant with the second field of the version message.
    pub sender: NetworkAddressWithoutTime,
    /// Node random nonce, randomly generated every time a version packet is sent. This nonce is used to detect connections to self.
    pub nonce: u64,
    /// User Agent (0x00 if string is 0 bytes long)
    pub user_agent: String,
    /// The last block received by the emitting node
    pub start_height: u32,
}}

impl_parse_deparse_each_field! {
// https://en.bitcoin.it/wiki/Protocol_documentation#version
#[derive(Debug, Clone, PartialEq, Hash, )]
pub struct VersionFields70001 {
    /// Whether the remote peer should announce relayed transactions or not, see BIP 0037
    pub relay: bool,
}}

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

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    #[repr(u32)]
    pub enum Magic {
        Main = 0xD9B4BEF9,
        Testnet = 0xDAB5BFFA,
        Testnet3 = 0x0709110B,
        Signet = 0x40CF030A,
        Namecoin = 0xFEB4BEF9,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn do_test<'a, T>(example_bin: impl IntoIterator<Item = &'a str>, expected: T)
    where
        for<'b> T: Parse,
        T: Deparse + PartialEq + std::fmt::Debug,
    {
        use pretty_assertions::assert_eq;
        use tap::Pipe;

        let example_bin = example_bin
            .into_iter()
            .flat_map(str::chars)
            .filter(char::is_ascii_alphanumeric)
            .collect::<String>()
            .pipe(hex::decode)
            .expect("example is not valid hex");

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
    fn test_version() {
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
                    receiver: NetworkAddressWithoutTime {
                        services: crate::constants::Services::NodeNetwork.into(),
                        ipv6: std::net::Ipv4Addr::UNSPECIFIED.to_ipv6_mapped(),
                        port: 0,
                    },
                },
                fields_106: VersionFields106 {
                    sender: NetworkAddressWithoutTime {
                        services: crate::constants::Services::NodeNetwork.into(),
                        ipv6: std::net::Ipv4Addr::UNSPECIFIED.to_ipv6_mapped(),
                        port: 0,
                    },
                    nonce: 7284544412836900411,
                    user_agent: String::from("/Satoshi:0.7.2/"),
                    start_height: 212672,
                },
            },
        );
    }
}
