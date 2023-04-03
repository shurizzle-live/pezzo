#![allow(dead_code, non_camel_case_types, unused_assignments)]

mod sysctl;

use std::io;

use sysctl::kinfo_proc;

use super::super::{Group, IAMContext, User};

impl super::super::process::ProcessContext {
    pub fn current(iam: &IAMContext) -> io::Result<Self> {
        let exe = std::env::current_exe()?;
        let pid = std::process::id();
        let sid = unsafe { libc::getsid(pid as i32) as u32 };

        let (uid, gid, ttyno) = {
            let ki_proc = super::proc_info::<kinfo_proc>(
                [
                    libc::CTL_KERN,
                    libc::KERN_PROC,
                    libc::KERN_PROC_PID,
                    pid as libc::c_int,
                ]
                .as_mut_slice(),
            )?;

            let uid = ki_proc.kp_eproc.e_pcred.p_ruid;
            let gid = ki_proc.kp_eproc.e_pcred.p_rgid;
            let ttyno = ki_proc.kp_eproc.e_tdev as u32;
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
