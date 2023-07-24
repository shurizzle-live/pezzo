pub trait Error: core::fmt::Display + core::fmt::Debug {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }
}

impl Error for core::fmt::Error {}
