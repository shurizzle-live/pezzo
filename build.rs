use std::{env, fs::File, io::BufWriter, path::PathBuf};

fn main() {
    prefix();
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum Os {
    Apple,
    FreeBSD,
    DragonflyBSD,
    NetBSD,
    OpenBSD,
    Linux,
}

static mut OS: Option<Os> = None;
fn os() -> Os {
    unsafe {
        if let Some(os) = OS {
            os
        } else {
            let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap();
            let os = match os.as_str() {
                "macos" | "ios" | "watchos" | "tvos" => Os::Apple,
                "freebsd" => Os::FreeBSD,
                "dragonfly" => Os::DragonflyBSD,
                "netbsd" => Os::NetBSD,
                "openbsd" => Os::OpenBSD,
                "linux" => Os::Linux,
                _ => panic!("unsupported OS {os}"),
            };
            OS = Some(os);
            os
        }
    }
}

fn default_prefix() -> Vec<u8> {
    match os() {
        Os::Apple | Os::FreeBSD | Os::DragonflyBSD => b"/usr/local\0".to_vec(),
        Os::NetBSD => b"/usr/pkg\0".to_vec(),
        Os::OpenBSD => b"\0".to_vec(),
        Os::Linux => b"\0".to_vec(),
    }
}

fn canonicalize_path(path: String) -> Vec<u8> {
    if path.is_empty() {
        let mut buf = path.into_bytes();
        buf.push(b'\0');
        return buf;
    }

    if unsafe { *path.as_bytes().get_unchecked(0) } != b'/' {
        panic!("prefix is not absolute");
    }

    enum Component<'a> {
        DirUp,
        Dir(&'a [u8]),
    }

    struct Iter<'a>(&'a [u8]);
    impl<'a> Iterator for Iter<'a> {
        type Item = Component<'a>;

        fn next(&mut self) -> Option<Self::Item> {
            loop {
                if self.0.is_empty() {
                    return None;
                }

                if let Some(pos) = memchr::memchr(b'/', self.0) {
                    let comp = unsafe { self.0.get_unchecked(..pos) };
                    self.0 = unsafe { self.0.get_unchecked(pos + 1..) };
                    match comp {
                        b"" => (),
                        b"." => (),
                        b".." => return Some(Component::DirUp),
                        dir => {
                            if memchr::memchr(b'\0', comp).is_some() {
                                panic!("Invalid null character in path")
                            } else {
                                return Some(Component::Dir(dir));
                            }
                        }
                    }
                } else {
                    self.0 = unsafe { self.0.get_unchecked(self.0.len()..) };
                }
            }
        }
    }

    let mut buf = b"/".to_vec();
    for comp in Iter(unsafe { path.as_bytes().get_unchecked(1..) }) {
        match comp {
            Component::DirUp if buf == b"/" => (),
            Component::DirUp => {
                unsafe { buf.set_len(memchr::memrchr(b'/', &buf).unwrap()) };
                if buf != b"/" {
                    buf.pop();
                }
            }
            Component::Dir(d) => {
                if buf != b"/" {
                    buf.push(b'/');
                }
                buf.extend_from_slice(d);
            }
        }
    }
    if buf == b"/" {
        buf.pop();
    }
    buf.push(b'\0');

    buf
}

fn prefix() {
    use std::io::Write;

    println!("cargo:rerun-if-env-changed=PREFIX");

    let prefix = std::env::var("PREFIX")
        .ok()
        .map(canonicalize_path)
        .unwrap_or_else(default_prefix);

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap()).join("paths.rs");
    let mut f = BufWriter::new(File::create(out_path).unwrap());

    writeln!(
        f,
        "pub const PREFIX: [u8; {}] = {:?};",
        prefix.len(),
        prefix
    )
    .unwrap();

    let mut config = prefix;
    config.pop();
    config.extend_from_slice(b"/etc/pezzo.conf\0");

    writeln!(
        f,
        "pub const CONFIG_PATH: [u8; {}] = {:?};",
        config.len(),
        config
    )
    .unwrap();
}
