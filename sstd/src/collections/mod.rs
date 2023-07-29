pub use alloc_crate::collections::*;
mod hash;

pub mod hash_map {
    pub use super::hash::map::*;
}

pub use self::hash_map::HashMap;
