mod parser;

pub use globset::GlobSet;
pub use parser::{Origin, Rule, Target};

pub struct Rules(Vec<parser::Rule>);

impl Rules {
    #[inline]
    pub fn rules(&self) -> &[parser::Rule] {
        &self.0
    }
}

#[inline]
pub fn parse<B: AsRef<[u8]>>(buf: B) -> std::result::Result<Rules, peg::error::ParseError<usize>> {
    parser::parse(buf.as_ref()).map(Rules)
}
