#![allow(dead_code, non_camel_case_types, unused_assignments)]

use std::{ffi::CStr, io, mem, os::raw::c_void, path::PathBuf, ptr, sync::Arc};

use super::{Group, User};

#[repr(C)]
#[derive(Clone, Copy)]
struct _pcred {
    pub pc_lock: [i8; 72],
    pub pc_ucred: *mut c_void,
    pub p_ruid: libc::uid_t,
    pub p_svuid: libc::uid_t,
    pub p_rgid: libc::gid_t,
    pub p_svgid: libc::gid_t,
    pub p_refcnt: libc::c_int,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct _ucred {
    pub cr_ref: i32,
    pub cr_uid: libc::uid_t,
    pub cr_ngroups: libc::c_short,
    pub cr_groups: [libc::gid_t; 16],
}

type caddr_t = *mut i8;

#[repr(C)]
#[derive(Clone, Copy)]
struct vmspace {
    dummy: i32,
    dummy2: caddr_t,
    dummy3: [i32; 5],
    dummy4: [caddr_t; 3],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct __extern_proc_p_un_p_st1 {
    __p_forw: *mut c_void,
    __p_back: *mut c_void,
}

#[repr(C)]
#[derive(Clone, Copy)]
union __extern_proc_p_un {
    p_st1: __extern_proc_p_un_p_st1,
    __p_starttime: libc::timeval,
}

type fixpt_t = u32;

#[repr(C)]
#[derive(Clone, Copy)]
struct extern_proc {
    p_un: __extern_proc_p_un,
    p_vmspace: *mut c_void,
    p_sigacts: *mut c_void,
    p_flag: libc::c_int,
    p_stat: i8,
    p_pid: libc::pid_t,
    p_oppid: libc::pid_t,
    p_dupfd: libc::c_int,
    user_stack: caddr_t,
    exit_thread: *mut c_void,
    p_debugger: libc::c_int,
    sigwait: libc::boolean_t,
    p_estcpu: libc::c_uint,
    p_cpticks: libc::c_int,
    p_pctcpu: fixpt_t,
    p_wchan: *mut c_void,
    p_wmesg: *mut c_void,
    p_swtime: libc::c_uint,
    p_slptime: libc::c_uint,
    p_realtimer: libc::itimerval,
    p_rtime: libc::timeval,
    p_uticks: u64,
    p_sticks: u64,
    p_iticks: u64,
    p_traceflag: libc::c_int,
    p_tracep: *mut c_void,
    p_siglist: libc::c_int,
    p_textvp: *mut c_void,
    p_holdcnt: libc::c_int,
    p_sigmask: libc::sigset_t,
    p_sigignore: libc::sigset_t,
    p_sigcatch: libc::sigset_t,
    p_priority: u8,
    p_usrpri: u8,
    p_nice: i8,
    p_comm: [i8; 17],
    p_pgrp: *mut c_void,
    p_addr: *mut c_void,
    p_xstat: libc::c_ushort,
    p_acflag: libc::c_ushort,
    p_ru: *mut c_void,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct eproc {
    e_paddr: *mut c_void,
    e_sess: *mut c_void,
    e_pcred: _pcred,
    e_ucred: _ucred,
    e_vm: vmspace,
    e_ppid: libc::pid_t,
    e_pgid: libc::pid_t,
    e_jobc: libc::c_short,
    e_tdev: libc::dev_t,
    e_tpgid: libc::pid_t,
    e_tsess: *mut c_void,
    e_wmesg: [i8; 8],
    e_xsize: i32,
    e_xrssize: libc::c_short,
    e_xccount: libc::c_short,
    e_xswrss: libc::c_short,
    e_flag: i32,
    e_login: [i8; 12],
    e_spare: [i32; 4],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct kinfo_proc {
    kp_proc: extern_proc,
    kp_eproc: eproc,
}

impl super::process::ProcessContext {
    pub fn current() -> io::Result<Self> {
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

        let user_name = unsafe {
            *libc::__error() = 0;
            let pwd = libc::getpwuid(uid);
            if pwd.is_null() {
                if *libc::__error() == 0 {
                    return Err(io::Error::new(io::ErrorKind::NotFound, "invalid user"));
                } else {
                    return Err(io::Error::last_os_error());
                }
            } else {
                CStr::from_ptr((*pwd).pw_name).to_owned()
            }
        };

        let group_name = unsafe {
            *libc::__error() = 0;
            let grd = libc::getgrgid(gid);
            if grd.is_null() {
                if *libc::__error() == 0 {
                    return Err(io::Error::new(io::ErrorKind::NotFound, "invalid group"));
                } else {
                    return Err(io::Error::last_os_error());
                }
            } else {
                CStr::from_ptr((*grd).gr_name).to_owned()
            }
        };

        let original_user = User {
            name: user_name,
            id: uid,
        };

        let original_group = Group {
            name: group_name,
            id: gid,
        };

        Ok(Self {
            exe,
            pid,
            original_user,
            original_group,
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
