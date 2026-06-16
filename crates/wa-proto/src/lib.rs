#![forbid(unsafe_code)]
#![allow(clippy::derive_partial_eq_without_eq)]

pub mod proto {
    #![allow(clippy::large_enum_variant)]

    include!("generated.rs");
}
