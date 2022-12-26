macro_rules! alias {
    ($($ident:ident: $parent:ident),* $(,)?) => {
        $(
            #[allow(non_camel_case_types)]
            pub type $ident = zerocopy::$parent<zerocopy::LittleEndian>;
        )*
    };
}
alias!(u32le: U32, i32le: I32, u64le: U64, i64le: I64);

pub trait Deparse {
    /// The size of buffer required to deparse this struct (including all fields)
    fn deparsed_len(&self) -> usize;
    /// Deparse this struct into a buffer
    fn deparse(&self, buffer: &mut [u8]);
}

macro_rules! as_bytes {
    ($($ty:ty),* $(,)?) => {
        $(
            impl $crate::deparse::Deparse for $ty {
                fn deparsed_len(&self) -> usize {
                    std::mem::size_of::<Self>()
                }

                fn deparse(&self, buffer: &mut [u8]) {
                    use zerocopy::AsBytes;
                    for (src, dst) in self.as_bytes().iter().zip(buffer) {
                        *dst = *src
                    }
                }
            }
        )*
    };
}

as_bytes!(u32le, i32le, u64le, i64le);

impl<const N: usize> Deparse for [u8; N] {
    fn deparsed_len(&self) -> usize {
        std::mem::size_of::<Self>()
    }

    fn deparse(&self, buffer: &mut [u8]) {
        use zerocopy::AsBytes;
        for (src, dst) in self.as_bytes().iter().zip(buffer) {
            *dst = *src
        }
    }
}

// bargain bucket derive macro
macro_rules! using_fields {
    (
        $(#[$struct_meta:meta])*
        $struct_vis:vis struct $struct_ident:ident {
            $(
                $(#[$field_meta:meta])*
                $field_vis:vis $field_name:ident: $field_ty:ty,
            )*
        }
    ) => {
        $(#[$struct_meta])*
        $struct_vis struct $struct_ident {
            $(
                $(#[$field_meta])*
                $field_vis $field_name: $field_ty,
            )*
        }
        impl $crate::deparse::Deparse for $struct_ident {
            fn deparsed_len(&self) -> usize {
                [
                    $(
                        <$field_ty as $crate::deparse::Deparse>::deparsed_len(&self.$field_name),
                    )*
                ].into_iter().sum()
            }
            fn deparse(&self, buffer: &mut [u8]) {
                let buffer = &mut buffer[0..];
                $(
                    <$field_ty as $crate::deparse::Deparse>::deparse(&self.$field_name, buffer);
                    let buffer = &mut buffer[<$field_ty as $crate::deparse::Deparse>::deparsed_len(&self.$field_name)..];
                )*
                let _ = buffer;
            }
        }
    };
}

using_fields!(
    #[repr(C)]
    pub struct Header {
        /// Magic value indicating message origin network, and used to seek to next message when stream state is unknown
        pub magic: u32le,
        /// ASCII string identifying the packet content, NULL padded (non-NULL padding results in packet rejected)
        pub command: [u8; 12],
        /// Length of payload in number of bytes
        pub length: u32le,
        /// First 4 bytes of sha256(sha256(payload))
        pub checksum: [u8; 4],
    }
);

#[test]
fn deparse_header() {
    let header = Header {
        magic: 0xD9B4BEF9.into(),
        command: *b"version\0\0\0\0\0",
        length: 100.into(),
        checksum: [0x35, 0x8d, 0x49, 0x32],
    };
    let mut buffer = vec![0u8; header.deparsed_len()];
    header.deparse(&mut buffer);
    println!("{buffer:x?}")
}
