#![doc = include_str!("../README.md")]
#![warn(
    missing_debug_implementations,
    missing_docs,
    unreachable_pub,
    rustdoc::all
)]
#![deny(unused_must_use, rust_2018_idioms)]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]
#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![no_std]

extern crate alloc;

#[macro_use]
extern crate tracing;

mod traits;
pub use traits::EigenDABlobProvider;

mod eigenda;
pub use eigenda::EigenDADataSource;

mod eigenda_blobs;
pub use eigenda_blobs::EigenDABlobSource;

mod eigenda_data;
pub use eigenda_data::EigenDABlobData;

mod v1_certificate;
pub use v1_certificate::BlobInfo;

mod version;
pub use version::CertVersion;

mod altda_commitment;
pub use altda_commitment::{AltDACommitment, EigenDAVersionedCert};

mod errors;
pub use errors::{BlobDecodingError, HokuleaErrorKind, HokuleaStatelessError};

mod constant;
pub use constant::BYTES_PER_FIELD_ELEMENT;
pub use constant::PAYLOAD_ENCODING_VERSION_0;
pub use constant::STALE_GAP;
