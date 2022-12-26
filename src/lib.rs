pub mod deparse;

use std::borrow::Cow;

#[derive(Debug, Clone, PartialEq, Hash)]
pub struct Message<'a> {
    pub magic: Magic,
    pub body: MessageBody<'a>,
}

#[derive(Debug, Clone, Copy, PartialEq, Hash)]
pub enum Magic {
    WellKnown(constants::Magic),
    Other(u32),
}

#[derive(Debug, Clone, PartialEq, Hash)]
pub enum MessageBody<'a> {
    Version(Version<'a>),
    Verack,
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
pub enum Version<'a> {
    Basic {
        version: VersionBasic,
        fields: VersionFieldsMandatory,
    },
    Supports106 {
        version: Version106,
        fields: VersionFieldsMandatory,
        fields_106: VersionFields106<'a>,
    },
    Supports70001 {
        version: Version70001,
        fields: VersionFieldsMandatory,
        fields_106: VersionFields106<'a>,
        fields_70001: VersionFields70001,
    },
}

impl<'a> nom_derive::Parse<&'a [u8]> for Version<'a> {
    fn parse(initial_input: &'a [u8]) -> nom::IResult<&'a [u8], Self> {
        let (rem, version) = u32::parse_le(initial_input)?;
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

impl Version<'_> {
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

// https://en.bitcoin.it/wiki/Protocol_documentation#version
#[derive(Debug, Clone, PartialEq, Hash, nom_derive::Nom)]
pub struct VersionFieldsMandatory {
    /// Bitfield of features to be enabled for this connection.
    #[nom(Parse = "parse::bitbag")]
    pub services: bitbag::BitBag<crate::constants::Services>,
    /// Standard UNIX timestamp in seconds.
    #[nom(Parse = "parse::timestamp")]
    pub timestamp: chrono::NaiveDateTime,
    /// The network address of the node receiving this message.
    pub receiver: SocketAddrAndServices,
}

// https://en.bitcoin.it/wiki/Protocol_documentation#version
#[derive(Debug, Clone, PartialEq, Hash, nom_derive::Nom)]
pub struct VersionFields106<'a> {
    /// Field can be ignored.
    /// This used to be the network address of the node emitting this message, but most P2P implementations send 26 dummy bytes.
    /// The "services" field of the address would also be redundant with the second field of the version message.
    pub sender: SocketAddrAndServices,
    /// Node random nonce, randomly generated every time a version packet is sent. This nonce is used to detect connections to self.
    #[nom(LittleEndian)]
    pub nonce: u64,
    /// User Agent (0x00 if string is 0 bytes long)
    #[nom(Parse = "parse::var_str")]
    pub user_agent: Cow<'a, str>,
    /// The last block received by the emitting node
    #[nom(LittleEndian)]
    pub start_height: u32,
}

// https://en.bitcoin.it/wiki/Protocol_documentation#version
#[derive(Debug, Clone, PartialEq, Hash, nom_derive::Nom)]
pub struct VersionFields70001 {
    /// Whether the remote peer should announce relayed transactions or not, see BIP 0037
    #[nom(Parse = "parse::bool")]
    pub relay: bool,
}

// https://en.bitcoin.it/wiki/Protocol_documentation#version
#[derive(Debug, Clone, PartialEq, Hash, nom_derive::Nom)]
pub struct SocketAddrAndServices {
    /// See [VersionFieldsMandatory::services]
    #[nom(Parse = "parse::bitbag")]
    pub services: bitbag::BitBag<crate::constants::Services>,
    /// The original client only supported IPv4 and only read the last 4 bytes to get the IPv4 address.
    /// However, the IPv4 address is written into the message as a 16 byte IPv4-mapped IPv6 address.
    ///    (12 bytes 00 00 00 00 00 00 00 00 00 00 FF FF, followed by the 4 bytes of the IPv4 address).
    #[nom(Parse = "parse::socket_addr")]
    pub address: std::net::SocketAddrV6,
}

mod parse {
    use std::borrow::Cow;

    use nom_derive::Parse as _;
    use tap::Pipe as _;
    use zerocopy::{LE, U32};

    pub fn bitbag<'a, BitBaggableT>(
        initial_input: &'a [u8],
    ) -> nom::IResult<&'a [u8], bitbag::BitBag<BitBaggableT>>
    where
        BitBaggableT: bitbag::BitBaggable,
        BitBaggableT::Repr: nom_derive::Parse<&'a [u8]>,
    {
        BitBaggableT::Repr::parse_le(initial_input)
            .map(|(rem, repr)| (rem, bitbag::BitBag::new_unchecked(repr)))
    }

    pub fn socket_addr<'a>(
        initial_input: &'a [u8],
    ) -> nom::IResult<&'a [u8], std::net::SocketAddrV6> {
        let (rem, ipv6) = u128::parse_be(initial_input)?;
        let (rem, port) = u16::parse_be(rem)?;
        let addr = std::net::SocketAddrV6::new(std::net::Ipv6Addr::from(ipv6), port, 0, 0);
        Ok((rem, addr))
    }

    pub fn bool(initial_input: &[u8]) -> nom::IResult<&[u8], bool> {
        let (rem, byte) = <u8 as nom_derive::Parse<&[u8]>>::parse(initial_input)?;
        match byte {
            1 => Ok((rem, true)),
            0 => Ok((rem, false)),
            // TODO(aatifsyed) plumb the errors here properly
            _ => Err(nom::Err::Error(nom::error::Error::new(
                initial_input,
                nom::error::ErrorKind::Alt,
            ))),
        }
    }

    pub fn var_int<'a>(initial_input: &'a [u8]) -> nom::IResult<&'a [u8], u64> {
        let (rem, i) = {
            let (rem, first_byte) = u8::parse(initial_input)?;
            match first_byte {
                // 0xFF followed by the length as uint64_t
                0xFF => u64::parse_le(rem)?,
                // 0xFE followed by the length as uint32_t
                0xFE => u32::parse_le(rem)?.pipe(|(rem, i)| (rem, i as u64)),
                // 0xFD followed by the length as uint16_t
                0xFD => u16::parse_le(rem)?.pipe(|(rem, i)| (rem, i as u64)),
                i => (rem, i.into()),
            }
        };
        Ok((rem, i))
    }

    pub fn var_str<'a>(initial_input: &'a [u8]) -> nom::IResult<&'a [u8], Cow<'a, str>> {
        let (rem, length) = var_int(initial_input)?;
        let (rem, s) = nom::combinator::map_res(
            // should fail to compile on 32-bit platforms, as nom::traits::ToUsize isn't implemented for u64 on those platforms
            // so we should be arithmetically safe
            nom::bytes::streaming::take(length),
            std::str::from_utf8,
        )(rem)?;
        Ok((rem, Cow::Borrowed(s)))
    }

    pub fn timestamp<'a>(initial_input: &'a [u8]) -> nom::IResult<&'a [u8], chrono::NaiveDateTime> {
        let (rem, timestamp) =
            nom::combinator::map_res(u64::parse_le, i64::try_from)(initial_input)?;
        let timestamp = chrono::NaiveDateTime::from_timestamp_opt(timestamp.into(), 0).ok_or(
            nom::Err::Error(nom::error::make_error(
                initial_input,
                nom::error::ErrorKind::MapOpt,
            )),
        )?;
        Ok((rem, timestamp))
    }

    pub fn u32_le<'a>(initial_input: &'a [u8]) -> nom::IResult<&'a [u8], U32<LE>> {
        let (rem, u) = u32::parse_le(initial_input)?;
        Ok((rem, U32::from_bytes(u.to_le_bytes())))
    }
}

mod wire {
    use zerocopy::byteorder::{LE, U32};

    // https://en.bitcoin.it/wiki/Protocol_documentation#Message_structure
    #[derive(Debug, zerocopy::AsBytes, nom_derive::Nom, Clone, Copy, PartialEq, Eq, Hash)]
    #[repr(C)]
    pub struct Header {
        #[nom(Parse = "crate::parse::u32_le")]
        /// Magic value indicating message origin network, and used to seek to next message when .stream state is unknown
        pub magic: U32<LE>,
        /// ASCII string identifying the packet content, NULL padded (non-NULL padding results in .packet rejected)
        pub command: [u8; 12],
        /// Length of payload in number of bytes.
        #[nom(Parse = "crate::parse::u32_le")]
        pub length: U32<LE>,
        /// First 4 bytes of sha256(sha256(payload)).
        pub checksum: [u8; 4],
    }
}

pub mod constants {
    #[derive(Debug, bitbag::BitBaggable, Clone, Copy, PartialEq, Eq, Hash)]
    #[repr(u64)]
    pub enum Services {
        ///	`NODE_NETWORK`
        /// This node can be asked for full blocks instead of just headers.
        NodeNetwork = 1,
        ///	`NODE_GETUTXO`
        /// See BIP 0064.
        NodeGetutxo = 2,
        ///	`NODE_BLOOM`
        /// See BIP 0111.
        NodeBloom = 4,
        ///	`NODE_WITNESS`
        /// See BIP 0144.
        NodeWitness = 8,
        ///	`NODE_XTHIN`
        /// Never formally proposed (as a BIP), and discontinued. Was historically sporadically seen on the network.
        NodeXthin = 16,
        ///	`NODE_COMPACT_FILTERS`
        /// See BIP 0157.
        NodeCompactFilters = 64,
        ///	`NODE_NETWORK_LIMITED`
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
    use nom_derive::Parse;
    use pretty_assertions::assert_eq;

    fn decode_hex<'a>(s: impl IntoIterator<Item = &'a str>) -> Vec<u8> {
        use tap::Pipe;

        s.into_iter()
            .flat_map(str::chars)
            .filter(char::is_ascii_alphanumeric)
            .collect::<String>()
            .pipe(hex::decode)
            .expect("input is not valid hex")
    }

    #[test]
    fn test_parse_var_str() {
        let input = decode_hex(["0F 2F 53 61 74 6F 73 68 69 3A 30 2E 37 2E 32 2F"]);
        let (rem, str) = parse::var_str(&input).unwrap();
        assert_eq!(0, rem.len());
        assert_eq!(str, "/Satoshi:0.7.2/");
    }

    #[test]
    fn test_parse_version() {
        let input = decode_hex([
            "62 EA 00 00",             // - 60002 (protocol version 60002)
            "01 00 00 00 00 00 00 00", // - 1 (NODE_NETWORK services)
            "11 B2 D0 50 00 00 00 00", // - Tue Dec 18 10:12:33 PST 2012
            "01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 FF FF 00 00 00 00 00 00", // - Recipient address info - see Network Address
            "01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 FF FF 00 00 00 00 00 00", // - Sender address info - see Network Address
            "3B 2E B3 5D 8C E6 17 65",                         // - Node ID
            "0F 2F 53 61 74 6F 73 68 69 3A 30 2E 37 2E 32 2F", // - "/Satoshi:0.7.2/" sub-version string (string is 15 bytes long)
            "C0 3E 03 00", // - Last block sending node has is block #212672
        ]);
        let (rem, version) = Version::parse(&input).unwrap();
        assert_eq!(
            version,
            Version::Supports106 {
                version: 60002.try_into().unwrap(),
                fields: VersionFieldsMandatory {
                    services: crate::constants::Services::NodeNetwork.into(),
                    timestamp: "2012-12-18T18:12:33".parse().unwrap(),
                    receiver: SocketAddrAndServices {
                        services: crate::constants::Services::NodeNetwork.into(),
                        address: std::net::SocketAddrV6::new(
                            std::net::Ipv4Addr::UNSPECIFIED.to_ipv6_mapped(),
                            0,
                            0,
                            0
                        )
                    }
                },
                fields_106: VersionFields106 {
                    sender: SocketAddrAndServices {
                        services: crate::constants::Services::NodeNetwork.into(),
                        address: std::net::SocketAddrV6::new(
                            std::net::Ipv4Addr::UNSPECIFIED.to_ipv6_mapped(),
                            0,
                            0,
                            0
                        )
                    },
                    nonce: 7284544412836900411,
                    user_agent: Cow::Borrowed("/Satoshi:0.7.2/"),
                    start_height: 212672
                }
            }
        );
        assert_eq!(0, rem.len());
    }

    #[test]
    fn test_parse_header() {
        let input = decode_hex([
            "F9 BE B4 D9",                         // - Main network magic bytes
            "76 65 72 73 69 6F 6E 00 00 00 00 00", // - "version" command
            "64 00 00 00",                         // - Payload is 100 bytes long
            "35 8d 49 32",                         // - payload checksum (internal byte order)
        ]);
        let (rem, header) = wire::Header::parse(&input).unwrap();
        assert_eq!(
            header,
            wire::Header {
                magic: (crate::constants::Magic::Main as u32).into(),
                command: *b"version\0\0\0\0\0",
                length: 100.into(),
                checksum: [0x35, 0x8d, 0x49, 0x32]
            }
        );
        assert_eq!(0, rem.len());
    }
}
