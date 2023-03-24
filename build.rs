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
        .ctypes_prefix("libc")
        .parse_callbacks(Box::new(UseCInt));

    let bindings = builder.generate().expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap()).join("bindings");

    _ = fs::create_dir(&out_path);

    bindings
        .write_to_file(out_path.join("pam.rs"))
        .expect("Couldn't write bindings!");
}
