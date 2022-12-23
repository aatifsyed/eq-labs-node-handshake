use nom_derive::Parse;

/// https://en.bitcoin.it/wiki/Protocol_documentation
pub mod wire {
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
        pub checksum: u32,
    }

    #[derive(Debug, nom_derive::Nom, Clone, Copy, PartialEq, Eq, Hash)]
    #[repr(C)]
    pub struct NetworkAddressWithoutTimestamp {
        /// See [Version::services].
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

    #[derive(Debug, nom_derive::Nom, Clone, Copy, PartialEq, Eq, Hash)]
    #[repr(C)]
    pub struct Version {
        /// Identifies protocol version being used by the node.
        #[nom(LittleEndian)]
        pub version: u32,
        /// Bitfield of features to be enabled for this connection.
        pub services: u64,
        /// Standard UNIX timestamp in seconds.
        #[nom(LittleEndian)]
        pub timestamp: u64,
        /// The network address of the node receiving this message
        pub addr_recv: NetworkAddressWithoutTimestamp,
    }

    #[cfg(test)]
    mod tests {
        use nom_derive::Parse;

        use super::*;
        #[test]
        fn example_header() {
            let s = concat!(
                "F9 BE B4 D9 76 65 72 73  69 6F 6E 00 00 00 00 00", // ....version.....
                "55 00 00 00 9C 7C 00 00  01 00 00 00 00 00 00 00", // U....|..........
                "E6 15 10 4D 00 00 00 00  01 00 00 00 00 00 00 00", // ...M............
                "00 00 00 00 00 00 00 00  00 00 FF FF 0A 00 00 01", // ................
                "20 8D 01 00 00 00 00 00  00 00 00 00 00 00 00 00", // ................
                "00 00 00 00 FF FF 0A 00  00 02 20 8D DD 9D 20 2C", // .......... ... ,
                "3A B4 57 13 00 55 81 01  00                     ", // :.W..U...
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
                    length: 85,
                    checksum: 0
                }
            )
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
