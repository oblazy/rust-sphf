//! Smooth Projective Hash Functions using curve25519-dalek
//!
//! # Examples
//!
//! ```
//! # // TODO (if you put code here it'll run as a test and also show up
//! # //       in the crate-level documentation!)
//! ```

extern crate clear_on_drop;
extern crate curve25519_dalek;
extern crate rand_core;
extern crate rand_os;
extern crate sha3;


mod sphf;

pub use crate::sphf::*;
