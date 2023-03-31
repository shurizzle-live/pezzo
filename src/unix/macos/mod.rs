#![allow(dead_code, non_camel_case_types, unused_assignments)]

mod sysctl;

use std::{ffi::CStr, io, mem, os::raw::c_void, path::PathBuf, ptr, sync::Arc};

use super::{Group, IAMContext, User};

use sysctl::kinfo_proc;

impl super::process::ProcessContext {
    pub fn current(iam: &IAMContext) -> io::Result<Self> {
        let exe = std::env::current_exe()?;
        let pid = std::process::id();
        let sid = unsafe { libc::getsid(pid as i32) as u32 };

        let (uid, gid, ttyno) = unsafe {
            let mut ki_proc: *mut kinfo_proc = ptr::null_mut();
            let mut size = mem::size_of::<kinfo_proc>();
            let mut mib = [
                libc::CTL_KERN,
                libc::KERN_PROC,
                libc::KERN_PROC_PID,
                pid as libc::c_int,
            ];

            let mut rc = 0;
            loop {
                {
                    size += size / 10;
                    let kp = libc::realloc(ki_proc as *mut c_void, size) as *mut kinfo_proc;
                    if kp.is_null() {
                        rc = -1;
                        break;
                    }
                    ki_proc = kp;
                }

                rc = libc::sysctl(
                    mib.as_mut_ptr(),
                    4,
                    ki_proc as *mut _,
                    &mut size,
                    ptr::null_mut(),
                    0,
                );

                if rc != -1 || *libc::__error() != libc::ENOMEM {
                    break;
                }
            }

            if rc == -1 {
                let err = io::Error::last_os_error();
                if !ki_proc.is_null() {
                    libc::free(ki_proc as *mut _);
                }
                return Err(err);
            }

            let uid = (*ki_proc).kp_eproc.e_pcred.p_ruid;
            let gid = (*ki_proc).kp_eproc.e_pcred.p_rgid;
            let ttyno = (*ki_proc).kp_eproc.e_tdev as u32;
            libc::free(ki_proc as *mut _);
            (uid, gid, ttyno)
        };

        let user_name = if let Some(user_name) = iam.user_name_by_id(uid)? {
            user_name
        } else {
            return Err(io::Error::new(io::ErrorKind::NotFound, "invalid user"));
        };

        let group_name = if let Some(group_name) = iam.group_name_by_id(gid)? {
            group_name
        } else {
            return Err(io::Error::new(io::ErrorKind::NotFound, "invalid group"));
        };

        let original_user = User {
            name: user_name,
            id: uid,
        };

        let original_group = Group {
            name: group_name,
            id: gid,
        };

        let original_groups = iam.get_groups(original_user.name())?;

        Ok(Self {
            exe,
            pid,
            original_user,
            original_group,
            original_groups,
            sid,
            ttyno,
        })
    }
}

extern "C" {
    fn devname(dev: libc::dev_t, r#type: libc::mode_t) -> *const i8;
}

impl super::tty::TtyInfo {
    pub fn for_ttyno(ttyno: u32) -> io::Result<Self> {
        unsafe {
            if ttyno == mem::transmute::<_, u32>(-1) {
                return Err(io::Error::new(io::ErrorKind::NotFound, "invalid tty"));
            }

            let name = devname(ttyno as _, libc::S_IFCHR);
            if name.is_null() {
                return Err(io::Error::new(io::ErrorKind::NotFound, "invalid tty"));
            }

            let name = CStr::from_ptr(name).to_string_lossy();
            let mut path = b"/dev/".to_vec();
            path.extend_from_slice(name.as_bytes());
            path.push(b'\0');
            let mut path: PathBuf = PathBuf::from("/dev");
            path.push(&*name);

            Ok(Self {
                path: Arc::new(path),
                name: Arc::new(name.to_string().into_boxed_str()),
            })
        }
    }
}
