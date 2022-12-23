/// https://en.bitcoin.it/wiki/Protocol_documentation
pub mod wire {
    use tap::Pipe;

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct VarInt {
        pub inner: u64,
    }

    impl<'a, E> nom_derive::Parse<&'a [u8], E> for VarInt
    where
        E: nom::error::ParseError<&'a [u8]>,
    {
        fn parse(initial_input: &'a [u8]) -> nom::IResult<&'a [u8], Self, E> {
            let (rem, i) = {
                let (rem, first_byte) = u8::parse(initial_input)?;
                match first_byte {
                    // 0xFF followed by the length as uint64_t
                    0xFF => u64::parse_le(rem)?,
                    // 0xFE followed by the length as uint32_t
                    0xFE => u32::parse_le(rem)?.pipe(|(rem, i)| (rem, i as u64)),
                    // 0xFD followed by the length as uint16_t
                    0xFD => u16::parse_le(rem)?.pipe(|(rem, i)| (rem, i as u64)),
                    i => (rem, i as u64),
                }
            };
            Ok((rem, VarInt { inner: i }))
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq, Hash)]
    pub struct VarStr {
        pub inner: String,
    }

    impl<'a, E> nom_derive::Parse<&'a [u8], E> for VarStr
    where
        E: nom::error::ParseError<&'a [u8]>
            + nom::error::FromExternalError<&'a [u8], std::str::Utf8Error>,
    {
        fn parse(initial_input: &'a [u8]) -> nom::IResult<&'a [u8], Self, E> {
            let (rem, length) = VarInt::parse(initial_input)?;
            let (rem, s) = nom::combinator::map_res(
                // should fail to compile on 32-bit platforms, as nom::traits::ToUsize isn't implemented for u64 on those platforms
                // so we should be arithmetically safe
                nom::bytes::streaming::take(length.inner),
                std::str::from_utf8,
            )(rem)?;
            Ok((
                rem,
                Self {
                    inner: String::from(s),
                },
            ))
        }
    }

    #[derive(Debug, nom_derive::Nom, Clone, Copy, PartialEq, Eq, Hash)]
    #[repr(C)]
    pub struct Header {
        /// Magic value indicating message origin network, and used to seek to next message when .stream state is unknown
        pub magic: u32,
        /// ASCII string identifying the packet content, NULL padded (non-NULL padding results in .packet rejected)
        pub command: [u8; 12],
        /// Length of payload in number of bytes.
        #[nom(LittleEndian)]
        pub length: u32,
        /// First 4 bytes of sha256(sha256(payload)).
        pub checksum: [u8; 4],
    }

    #[derive(Debug, nom_derive::Nom, Clone, Copy, PartialEq, Eq, Hash)]
    #[repr(C)]
    pub struct NetworkAddressWithoutTimestamp {
        /// See [Version::services].
        #[nom(LittleEndian)]
        pub services: u64,
        /// Network byte order.
        /// The original client only supported IPv4 and only read the last 4 bytes to get the IPv4 address.
        /// However, the IPv4 address is written into the message as a 16 byte IPv4-mapped IPv6 address.
        ///    (12 bytes 00 00 00 00 00 00 00 00 00 00 FF FF, followed by the 4 bytes of the IPv4 address).
        pub ipv6_address: [u8; 16],
        /// Port number, network byte order.
        #[nom(BigEndian)]
        pub port: u16,
    }

    #[derive(Debug, nom_derive::Nom, Clone, PartialEq, Eq, Hash)]
    #[repr(C)]
    pub struct Version {
        /// Identifies protocol version being used by the node.
        #[nom(LittleEndian)]
        pub version: u32,
        /// Bitfield of features to be enabled for this connection.
        #[nom(LittleEndian)]
        pub services: u64,
        /// Standard UNIX timestamp in seconds.
        #[nom(LittleEndian)]
        pub timestamp: u64,
        /// The network address of the node receiving this message.
        pub addr_recv: NetworkAddressWithoutTimestamp,
        /// Field can be ignored.
        /// This used to be the network address of the node emitting this message, but most P2P implementations send 26 dummy bytes.
        /// The "services" field of the address would also be redundant with the second field of the version message.
        pub addr_from: NetworkAddressWithoutTimestamp,
        /// Node random nonce, randomly generated every time a version packet is sent. This nonce is used to detect connections to self.
        pub nonce: u64,
        /// User Agent (0x00 if string is 0 bytes long)
        pub user_agent: VarStr,
        /// The last block received by the emitting node
        #[nom(LittleEndian)]
        pub start_height: u32,
        /// Whether the remote peer should announce relayed transactions or not, see BIP 0037
        #[nom(Parse = "parse_bool")]
        pub relay: bool,
    }

    fn parse_bool(initial_input: &[u8]) -> nom::IResult<&[u8], bool> {
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

    #[cfg(test)]
    mod tests {
        use nom_derive::Parse;

        use super::*;
        #[test]
        fn example_header() {
            let s = concat!(
                // Message Header:
                "F9 BE B4 D9",                         // - Main network magic bytes
                "76 65 72 73 69 6F 6E 00 00 00 00 00", // - "version" command
                "64 00 00 00",                         // - Payload is 100 bytes long
                "35 8d 49 32",                         // - payload checksum (internal byte order)
                // Version message:
                "62 EA 00 00",             // - 60002 (protocol version 60002)
                "01 00 00 00 00 00 00 00", // - 1 (NODE_NETWORK services)
                "11 B2 D0 50 00 00 00 00", // - Tue Dec 18 10:12:33 PST 2012
                "01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 FF FF 00 00 00 00 00 00", // - Recipient address info - see Network Address
                "01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 FF FF 00 00 00 00 00 00", // - Sender address info - see Network Address
                "3B 2E B3 5D 8C E6 17 65", // - Node ID
                "0F 2F 53 61 74 6F 73 68 69 3A 30 2E 37 2E 32 2F                              ", // - "/Satoshi:0.7.2/" sub-version string (string is 15 bytes long)
                "C0 3E 03 00", // - Last block sending node has is block #212672
                "01",          // - relay
            )
            .chars()
            .filter(char::is_ascii_alphanumeric)
            .collect::<String>();
            let b = hex::decode(s).unwrap();
            let (rest, header) = Header::parse(&b).unwrap();
            assert_eq!(
                header,
                Header {
                    magic: crate::constants::Magic::Main as u32,
                    command: *b"version\0\0\0\0\0",
                    length: 100,
                    checksum: [0x35, 0x8d, 0x49, 0x32],
                }
            );
            let (rest, version) = Version::parse(&rest).unwrap();
            assert_eq!(
                version,
                Version {
                    version: 60002,
                    services: crate::constants::Services::NodeNetwork as _,
                    timestamp: 1355854353,
                    addr_recv: NetworkAddressWithoutTimestamp {
                        services: crate::constants::Services::NodeNetwork as _,
                        ipv6_address: std::net::Ipv4Addr::UNSPECIFIED.to_ipv6_mapped().octets(),
                        port: 0
                    },
                    addr_from: NetworkAddressWithoutTimestamp {
                        services: crate::constants::Services::NodeNetwork as _,
                        ipv6_address: std::net::Ipv4Addr::UNSPECIFIED.to_ipv6_mapped().octets(),
                        port: 0
                    },
                    nonce: u64::from_be_bytes([0x3B, 0x2E, 0xB3, 0x5D, 0x8C, 0xE6, 0x17, 0x65]),
                    user_agent: VarStr {
                        inner: String::from("/Satoshi:0.7.2/")
                    },
                    start_height: 212672,
                    relay: true
                }
            );
            assert_eq!(rest.len(), 0);
        }
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

    #[derive(Debug, bitbag::BitBaggable, Clone, Copy, PartialEq, Eq, Hash)]
    #[repr(u32)]
    pub enum Magic {
        Main = 0xF9BEB4D9,
        Testnet = 0xFABFB5DA,
        Testnet3 = 0x0B110907,
        Signet = 0x0A03CF40,
        Namecoin = 0xF9BEB4FE,
    }
}
