mod parser;

pub use globset::GlobSet;
pub use parser::{Env, Origin, Rule, Target};

use alloc_crate::vec::Vec;

pub struct Rules(Vec<parser::Rule>);

impl Rules {
    #[inline]
    pub fn rules(&self) -> &[parser::Rule] {
        &self.0
    }
}

#[inline]
pub fn parse<B: AsRef<[u8]>>(buf: B) -> core::result::Result<Rules, peg::error::ParseError<usize>> {
    parser::parse(buf.as_ref()).map(Rules)
}
