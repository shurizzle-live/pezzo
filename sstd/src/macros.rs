#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => {{
        $crate::io::_print(::core::format_args!($($arg)*));
    }};
}

#[macro_export]
macro_rules! println {
    () => {
        $crate::print!("\n")
    };
    ($fmt:literal $(,)?) => {{
        $crate::print!(concat!($fmt, "\n"));
    }};
    ($fmt:literal, $($arg:tt)*) => {{
        $crate::print!(concat!($fmt, "\n"), $($arg)*);
    }};
}

#[macro_export]
macro_rules! eprint {
    ($($arg:tt)*) => {{
        $crate::io::_eprint(::core::format_args!($($arg)*));
    }};
}

#[macro_export]
macro_rules! eprintln {
    () => {
        $crate::eprint!("\n")
    };
    ($fmt:literal $(,)?) => {{
        $crate::eprint!(concat!($fmt, "\n"));
    }};
    ($fmt:literal, $($arg:tt)*) => {{
        $crate::eprint!(concat!($fmt, "\n"), $($arg)*);
    }};
}
