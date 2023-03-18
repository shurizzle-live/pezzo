#[cfg(not(target_os = "linux"))]
pub mod noecho;
#[cfg(not(target_os = "linux"))]
pub mod uname;
