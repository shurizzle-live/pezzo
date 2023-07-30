#![no_std]

extern crate alloc as alloc_crate;

#[cfg(unix)]
#[path = "unix/mod.rs"]
pub(crate) mod sys;
#[macro_use]
mod macros;
pub use sys::*;

pub mod ffi {
    pub use alloc_crate::ffi::*;
    pub use core::ffi::*;
}

pub use alloc_crate::{borrow, boxed, rc, string, vec};
pub use core::{
    cell, clone, cmp, convert, default, fmt, hash, iter, marker, mem, ops, option, ptr, result,
    slice, str, sync,
};
pub mod collections;

pub mod prelude {
    pub mod v1 {
        pub use crate::{
            borrow::ToOwned,
            boxed::Box,
            clone::Clone,
            cmp::{Eq, Ord, PartialEq, PartialOrd},
            convert::{AsMut, AsRef, From, Into},
            default::Default,
            iter::{DoubleEndedIterator, ExactSizeIterator, Extend, IntoIterator, Iterator},
            marker::{Copy, Send, Sized, Sync, Unpin},
            mem::drop,
            ops::{Drop, Fn, FnMut, FnOnce},
            option::Option::{self, None, Some},
            result::Result::{self, Err, Ok},
            string::{String, ToString},
            vec::Vec,
        };
    }

    pub mod rust_2015 {
        pub use super::v1::*;
    }

    pub mod rust_2018 {
        pub use super::v1::*;
    }

    pub mod rust_2021 {
        pub use super::v1::*;
        pub use crate::{
            convert::{TryFrom, TryInto},
            iter::FromIterator,
        };
    }
}
