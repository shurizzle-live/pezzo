use std::{
    cell::RefCell,
    collections::HashSet,
    env,
    fmt::{self},
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    rc::Rc,
};

use bindgen::callbacks::{IntKind, ParseCallbacks};

static LINUX_RETURN_VALUES: phf::Map<&'static str, (&'static str, &'static str, &'static str)> = phf::phf_map! {
    "PAM_SUCCESS" => ("Success", "Successful function return", "Success"),
    "PAM_OPEN_ERR" => ("Open", "dlopen() failure when dynamically loading a service module", "Failed to load module"),
    "PAM_SYMBOL_ERR" => ("Symbol", "Symbol not found", "Symbol not found"),
    "PAM_SERVICE_ERR" => ("Service", "Error in service module", "Error in service module"),
    "PAM_SYSTEM_ERR" => ("System", "System error", "System error"),
    "PAM_BUF_ERR" => ("Buffer", "Memory buffer error", "Memory buffer error"),
    "PAM_PERM_DENIED" => ("PermissionDenied", "Permission denied", "Permission denied"),
    "PAM_AUTH_ERR" => ("Authentication", "Authentication failure", "Authentication failure"),
    "PAM_CRED_INSUFFICIENT" => (
        "InsufficientCredentials",
        "Can not access authentication data due to insufficient credentials",
        "Insufficient credentials to access authentication data"
    ),
    "PAM_AUTHINFO_UNAVAIL" => (
        "AuthenticationInfoUnavailable",
        "Underlying authentication service can not retrieve authentication information",
        "Authentication service cannot retrieve authentication info"
    ),
    "PAM_USER_UNKNOWN" => (
        "UnknownUser",
        "User not known to the underlying authentication module",
        "User not known to the underlying authentication module"
    ),
    "PAM_MAXTRIES" => (
        "MaximumRetries",
        "An authentication service has maintained a retry count which has been reached. No further retries should be attempted",
        "Have exhausted maximum number of retries for service"
    ),
    "PAM_NEW_AUTHTOK_REQD" => (
        "NewAuthenticationTokenRequired",
        "New authentication token required. This is normally returned if the machine security policies require that the password should be changed because the password is NULL or it has aged",
        "Authentication token is no longer valid; new one required"
    ),
    "PAM_ACCT_EXPIRED" => ("AccountExpired", "User account has expired", "User account has expired"),
    "PAM_SESSION_ERR" => (
        "Session",
        "Can not make/remove an entry for the specified session",
        "Cannot make/remove an entry for the specified session"
    ),
    "PAM_CRED_UNAVAIL" => (
        "CredentialsUnavailable",
        "Underlying authentication service can not retrieve user credentials unavailable",
        "Authentication service cannot retrieve user credentials"
    ),
    "PAM_CRED_EXPIRED" => ( "CredentialsExpired", "User credentials expired", "User credentials expired"),
    "PAM_CRED_ERR" => ("Credentials", "Failure setting user credentials", "Failure setting user credentials"),
    "PAM_NO_MODULE_DATA" => (
        "NoModuleData",
        "No module specific data is present",
        "No module specific data is present"
    ),
    "PAM_CONV_ERR" => ("Conversation", "Conversation error", "Conversation error"),
    "PAM_AUTHTOK_ERR" => (
        "AuthenticationToken",
        "Authentication token manipulation error",
        "Authentication token manipulation error"
    ),
    "PAM_AUTHTOK_RECOVERY_ERR" => (
        "AuthenticationRecovery",
        "Authentication information cannot be recovered",
        "Authentication information cannot be recovered"
    ),
    "PAM_AUTHTOK_LOCK_BUSY" => (
        "AuthenticationLockBusy",
        "Authentication token lock busy",
        "Authentication token lock busy"
    ),
    "PAM_AUTHTOK_DISABLE_AGING" => (
        "AuthenticationTokenAgingDisabled",
        "Authentication token aging disabled",
        "Authentication token aging disabled"
    ),
    "PAM_TRY_AGAIN" => (
        "TryAgain",
        "Preliminary check by password service",
        "Failed preliminary check by password service"
    ),
    "PAM_IGNORE" => (
        "Ignore",
        "Ignore underlying account module regardless of whether the control flag is required, optional, or sufficient",
        "The return value should be ignored by PAM dispatch"
    ),
    "PAM_ABORT" => ("Abort", "Critical error (?module fail now request)", "Critical error - immediate abort"),
    "PAM_AUTHTOK_EXPIRED" => (
        "AuthenticationTokenExpired",
        "user's authentication token has expired",
        "Authentication token expired"
    ),
    "PAM_MODULE_UNKNOWN" => ( "ModuleUnknown", "module is not known", "Module is unknown"),
    "PAM_BAD_ITEM" => ("BadItem","Bad item passed to pam_*_item()", "Bad item passed to pam_*_item()"),
    "PAM_CONV_AGAIN" => (
        "ConversationAgain",
        "conversation function is event driven and data is not available yet",
        "Conversation is waiting for event"
    ),
    "PAM_INCOMPLETE" => (
        "Incomplete",
        "please call this function again to complete authentication stack. Before calling again, verify that conversation is completed",
        "Application needs to call libpam again"
    ),
};

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=TARGET");
    println!("cargo:rerun-if-env-changed=CARGO_CFG_TARGET_OS");

    match os() {
        Os::Linux => main_linux(),
        Os::Apple => main_apple(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum Os {
    Apple,
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
                "linux" => Os::Linux,
                _ => panic!("unsupported OS {os}"),
            };
            OS = Some(os);
            os
        }
    }
}

#[inline]
fn main_linux() {
    linux_pam()
}

#[inline]
fn main_apple() {
    open_pam()
}

fn linux_pam() {
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());

    #[derive(Debug)]
    struct ErrorsConstants(Rc<RefCell<HashSet<String>>>);

    impl ParseCallbacks for ErrorsConstants {
        fn int_macro(&self, name: &str, _value: i64) -> Option<IntKind> {
            if LINUX_RETURN_VALUES.contains_key(name) {
                self.0.borrow_mut().insert(name.to_string());
            }
            Some(IntKind::I32)
        }
    }

    let bindings = {
        let errors = Rc::new(RefCell::new(HashSet::new()));
        let builder = bindgen::Builder::default()
            .header_contents("wrapper.h", "#include <security/pam_appl.h>")
            .parse_callbacks(Box::new(bindgen::CargoCallbacks))
            .ctypes_prefix("libc")
            .parse_callbacks(Box::new(ErrorsConstants(errors.clone())));

        Bindings::linux(
            builder.generate().expect("Unable to generate bindings"),
            RefCell::take(&errors),
        )
    };

    let mut f = File::create(out_path.join("pam.rs")).unwrap();
    let formatter = Formatter::new();
    formatter.format_in_file(bindings, &mut f);
}

fn open_pam() {
    unimplemented!()
}

pub struct Bindings(
    SysBindings,
    HashSet<String>,
    &'static phf::Map<&'static str, (&'static str, &'static str, &'static str)>,
);

impl Bindings {
    #[inline]
    pub fn linux(bindings: bindgen::Bindings, errors: HashSet<String>) -> Self {
        Self(SysBindings(bindings), errors, &LINUX_RETURN_VALUES)
    }
}

impl fmt::Display for Bindings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)?;
        fmt::Display::fmt(&PamError(self.2, &self.1), f)
    }
}

pub struct PamError<'a>(
    &'a phf::Map<&'static str, (&'static str, &'static str, &'static str)>,
    &'a HashSet<String>,
);

impl<'a> fmt::Display for PamError<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "#[repr(transparent)]")?;
        writeln!(
            f,
            "#[derive(Copy, Clone, PartialEq, PartialOrd, Eq, Ord, Hash)]"
        )?;
        writeln!(f, "#[non_exhaustive]")?;
        writeln!(f, "pub struct Error(pub(crate) i32);")?;
        writeln!(f, "#[allow(non_upper_case_globals)]")?;
        writeln!(f, "impl Error {{")?;

        for (&name, &(rname, doc, _)) in self.0 {
            if name != "PAM_SUCCESS" && self.1.contains(name) {
                if !doc.is_empty() {
                    writeln!(f, "/// {}", doc)?;
                }
                writeln!(f, "pub const {}: Self = Self(self::sys::{});", rname, name)?;
            }
        }

        writeln!(f, "}}")?;

        writeln!(f, "impl ::core::fmt::Display for Error {{")?;
        writeln!(
            f,
            "fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {{"
        )?;
        writeln!(f, "match self.0 {{")?;
        for (&name, &(rname, _, err)) in self.0 {
            if name != "PAM_SUCCESS" && self.1.contains(name) {
                writeln!(
                    f,
                    "self::sys::{} => write!(f, \"{{}} {} ({{}})\", self::sys::{}, {:?}),",
                    name, rname, name, err
                )?;
            }
        }
        writeln!(f, "no => write!(f, \"{{}} ? (Unknown PAM error)\", no),")?;
        writeln!(f, "}}")?;
        writeln!(f, "}}")?;
        writeln!(f, "}}")?;

        writeln!(f, "impl ::core::fmt::Debug for Error {{")?;
        writeln!(
            f,
            "fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {{"
        )?;
        writeln!(f, "match self.0 {{")?;
        for (&name, &(rname, _, _)) in self.0 {
            if name != "PAM_SUCCESS" && self.1.contains(name) {
                writeln!(f, "self::sys::{} => write!(f, \"Error::{}\"),", name, rname)?;
            }
        }
        writeln!(f, "no => write!(f, \"Error({{}})\", no),")?;
        writeln!(f, "}}")?;
        writeln!(f, "}}")?;
        writeln!(f, "}}")
    }
}

pub struct SysBindings(bindgen::Bindings);

impl fmt::Display for SysBindings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "pub mod sys {{")?;
        fmt::Display::fmt(&SysAllow, f)?;
        fmt::Display::fmt(&self.0, f)?;
        write!(f, "\n}}")
    }
}

pub struct SysAllow;

impl fmt::Display for SysAllow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "#![allow(
    non_upper_case_globals,
    non_camel_case_types,
    non_snake_case,
    deref_nullptr,
    dead_code
)]\n\n"
        )
    }
}

pub struct Formatter {
    bin: Option<Box<Path>>,
}

impl Formatter {
    pub fn new() -> Self {
        Self {
            bin: which::which("rustfmt").ok().map(PathBuf::into_boxed_path),
        }
    }

    pub fn null() -> Self {
        Self { bin: None }
    }

    #[inline]
    pub fn format<S: fmt::Display>(&self, code: S) -> String {
        let mut buf = String::new();
        self.format_in(code, &mut buf);
        buf
    }

    pub fn format_in<S: fmt::Display>(&self, code: S, buf: &mut String) {
        match self._format(code, Stdio::piped()) {
            Ok(mut child) => {
                if let Some(mut out) = child.stdout.take() {
                    out.read_to_string(buf).unwrap();
                }

                let status = child.wait().expect("Failed to format file");
                if !status.success() {
                    panic!("Failed to format file");
                }
            }
            Err((code, _)) => {
                use std::fmt::Write;
                write!(buf, "{}", code).unwrap()
            }
        }
    }

    #[cfg(windows)]
    pub fn format_in_file<S: fmt::Display>(&self, code: S, f: &mut File) {
        use std::os::windows::io::{AsRawHandle, FromRawHandle};
        match self._format(code, unsafe { Stdio::from_raw_handle(f.as_raw_handle()) }) {
            Ok(mut child) => {
                core::mem::forget(child.stdout.take());

                let status = child.wait().expect("Failed to format file");
                if !status.success() {
                    panic!("Failed to format file");
                }
            }
            Err((code, out)) => {
                core::mem::forget(out);
                write!(f, "{}", code).unwrap();
            }
        }
    }

    #[cfg(unix)]
    pub fn format_in_file<S: fmt::Display>(&self, code: S, f: &mut File) {
        use std::os::unix::io::{AsRawFd, FromRawFd};
        match self._format(code, unsafe { Stdio::from_raw_fd(f.as_raw_fd()) }) {
            Ok(mut child) => {
                core::mem::forget(child.stdout.take());

                let status = child.wait().expect("Failed to format file");
                if !status.success() {
                    panic!("Failed to format file");
                }
            }
            Err((code, out)) => {
                core::mem::forget(out);
                write!(f, "{}", code).unwrap();
            }
        }
    }

    fn _format<S: fmt::Display>(&self, code: S, out: Stdio) -> Result<Child, (S, Stdio)> {
        if let Some(ref bin) = self.bin {
            let mut child = Command::new(bin.as_os_str())
                .arg("--emit")
                .arg("stdout")
                .stderr(Stdio::inherit())
                .stdin(Stdio::piped())
                .stdout(out)
                .spawn()
                .expect("Failed to format file");

            // write code to stdin
            {
                let mut stdin = if let Some(stdin) = child.stdin.take() {
                    stdin
                } else {
                    panic!("Failed to format file");
                };
                write!(stdin, "{}", code).expect("Failed to format file");
                stdin.flush().expect("Failed to format file");
            }

            drop(child.stdin.take());
            drop(child.stderr.take());

            Ok(child)
        } else {
            Err((code, out))
        }
    }
}

impl Default for Formatter {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}
