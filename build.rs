use std::{env, fs, path::PathBuf};

use bindgen::callbacks::{IntKind, ParseCallbacks};

#[derive(Debug)]
struct UseCInt;

impl ParseCallbacks for UseCInt {
    fn int_macro(&self, _name: &str, _value: i64) -> Option<IntKind> {
        Some(IntKind::Int)
    }
}

fn main() {
    println!("cargo:rustc-link-lib=pam");
    println!("cargo:rerun-if-changed=build.rs");

    let builder = bindgen::Builder::default()
        .header_contents("wrapper.h", "#include <security/pam_appl.h>")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks));

    let builder = if cfg!(target_os = "linux") {
        builder
            .ctypes_prefix("libc")
            .parse_callbacks(Box::new(UseCInt))
    } else if cfg!(target_os = "macos") {
        builder
            .raw_line(
                r#"pub mod c {
        pub type c_char = ::libc::c_char;
        pub type c_int = ::libc::c_int;
        pub type c_uint = ::libc::c_int;
        pub type c_void = ::libc::c_void;
    }"#,
            )
            .ctypes_prefix("c")
    } else {
        builder
    };

    let bindings = builder.generate().expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap()).join("bindings");

    _ = fs::create_dir(&out_path);

    bindings
        .write_to_file(out_path.join("pam.rs"))
        .expect("Couldn't write bindings!");
}
