use std::{
    ffi::{c_int, c_long, c_uint, c_ulong, c_ulonglong, CString},
    fs::File,
    io::{self, Read},
    path::Path,
};

use crate::version;

/// Process state
#[repr(u8)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum State {
    #[default]
    /// Running
    Running,
    /// Sleeping in an interruptible wait
    Sleeping,
    /// Waiting in uninterruptible disk sleep
    Waiting,
    /// Zombie
    Zombie,
    /// Stopped (on a signal) or (before Linux 2.6.33) trace stopped
    Stopped,
    /// Tracing stop (Linux 2.6.33 onward)
    Tracing,
    /// Paging (only before Linux 2.6.0)
    Paging,
    /// Dead (from Linux 2.6.0 onward)
    Dead,
    /// Wakekill (Linux 2.6.33 to 3.13 only)
    Wakekill,
    /// Waking (Linux 2.6.33 to 3.13 only)
    Waking,
    /// Parked (Linux 3.9 to 3.13 only)
    Parked,
    /// Idle (Linux 4.14 onward)
    Idle,
}

/// Status information about the process.
#[derive(Debug, Default, Clone)]
pub struct Stat {
    /// The process ID.
    pub pid: u32,
    /// The filename of the executable, in parentheses. Strings longer than
    /// TASK_COMM_LEN (16) characters (including the terminating null byte) are
    /// silently truncated. This is visible whether or not the executable is
    /// swapped out.
    pub comm: CString,
    /// The state of the process.
    pub state: State,
    /// The PID of the parent of this process.
    pub ppid: u32,
    /// The process group ID of the process.
    pub pgrp: u32,
    /// The session ID of the process.
    pub session: u32,
    /// The controlling terminal of the process. (The minor device number is
    /// contained in the combination of bits 31 to 20 and 7 to 0; the major
    /// device number is in bits 15 to 8.)
    pub tty_nr: u32,
    /// The ID of the foreground process group of the controlling terminal of
    /// the process.
    ///
    /// 0xffffffff is -1 (none)
    pub tpgid: u32,
    /// The kernel flags word of the process. For bit meanings, see the PF_*
    /// defines in the Linux kernel source file include/linux/sched.h. Details
    /// depend on the kernel version.
    pub flags: c_ulong,
    /// The number of minor faults the process has made which have not required
    /// loading a memory page from disk.
    pub minflt: c_ulong,
    /// The number of minor faults that the process's waited-for children have
    /// made.
    pub cminflt: c_ulong,
    /// The number of major faults the process has made which have required
    /// loading a memory page from disk.
    pub majflt: c_ulong,
    /// The number of major faults that the process's waited-for children have
    /// made.
    pub cmajflt: c_ulong,
    /// Amount of time that this process has been scheduled in user mode,
    /// measured in clock ticks (divide by sysconf(_SC_CLK_TCK)).
    ///
    /// This includes guest time, guest_time (time spent running a virtual CPU,
    /// see below), so that applications that are not aware of the guest time
    /// field do not lose that time from their calculations.
    pub utime: c_ulong,
    /// Amount of time that this process has been scheduled in kernel mode,
    /// measured in clock ticks (divide by sysconf(_SC_CLK_TCK)).
    pub stime: c_ulong,
    /// Amount of time that this process's waited-for children have been
    /// scheduled in user mode, measured in clock ticks (divide by
    /// sysconf(_SC_CLK_TCK)). (See also times(2).) This includes guest time,
    /// cguest_time (time spent running a virtual CPU, see below).
    pub cutime: c_long,
    /// Amount of time that this process's waited-for children have been
    /// scheduled in kernel mode, measured in clock ticks (divide by
    /// sysconf(_SC_CLK_TCK)).
    pub cstime: c_long,
    /// (Explanation for Linux 2.6) For processes running a real- time
    /// scheduling policy (policy below; see sched_setscheduler(2)), this is the
    /// negated scheduling priority, minus one; that is, a number in the range
    /// -2 to -100, corresponding to real-time priorities 1 to 99. For processes
    /// running under a non-real-time scheduling policy, this is the raw nice
    /// value (setpriority(2)) as represented in the kernel. The kernel stores
    /// nice values as numbers in the range 0 (high) to 39 (low), corresponding
    /// to the user-visible nice range of -20 to 19.
    ///
    /// Before Linux 2.6, this was a scaled value based on the scheduler
    /// weighting given to this process.
    pub priority: c_long,
    /// The nice value (see setpriority(2)), a value in the range 19 (low
    /// priority) to -20 (high priority).
    pub nice: c_long,
    /// Number of threads in this process (since Linux 2.6). Before Linux 2.6,
    /// this field was hard coded to 0 as a placeholder for an earlier removed
    /// field.
    pub num_threads: c_long,
    /// The time in jiffies before the next SIGALRM is sent to the process due
    /// to an interval timer. Since Linux 2.6.17, this field is no longer
    /// maintained, and is hard coded as 0.
    pub itrealvalue: c_long,
    /// The time the process started after system boot. Before Linux 2.6, this
    /// value was expressed in jiffies. Since Linux 2.6, the value is expressed
    /// in clock ticks (divide by sysconf(_SC_CLK_TCK)).
    pub start_time: c_ulonglong,
    /// Virtual memory size in bytes.
    pub vsize: c_ulong,
    /// Resident Set Size: number of pages the process has in real memory. This
    /// is just the pages which count toward text, data, or stack space. This
    /// does not include pages which have not been demand-loaded in, or which
    /// are swapped out. This value is inaccurate; see /proc/pid/statm below.
    pub rss: c_long,
    /// Current soft limit in bytes on the rss of the process; see the
    /// description of RLIMIT_RSS in getrlimit(2).
    pub rsslim: c_ulong,
    /// The address above which program text can run.
    pub startcode: c_ulong,
    /// The address below which program text can run.
    pub endcode: c_ulong,
    /// The address of the start (i.e., bottom) of the stack.
    pub startstack: c_ulong,
    /// The current value of ESP (stack pointer), as found in the kernel stack
    /// page for the process.
    pub kstkesp: c_ulong,
    /// The current EIP (instruction pointer).
    pub kstkeip: c_ulong,
    /// The bitmap of pending signals, displayed as a decimal number. Obsolete,
    /// because it does not provide information on real-time signals; use
    /// /proc/pid/status instead.
    pub signal: c_ulong,
    /// The bitmap of blocked signals, displayed as a decimal number. Obsolete,
    /// because it does not provide information on real-time signals; use
    /// /proc/pid/status instead.
    pub blocked: c_ulong,
    /// The bitmap of ignored signals, displayed as a decimal number. Obsolete,
    /// because it does not provide information on real-time signals; use
    /// /proc/pid/status instead.
    pub sigignore: c_ulong,
    /// The bitmap of caught signals, displayed as a decimal number. Obsolete,
    /// because it does not provide information on real-time signals; use
    /// /proc/pid/status instead.
    pub sigcatch: c_ulong,
    /// This is the "channel" in which the process is waiting. It is the address
    /// of a location in the kernel where the process is sleeping. The
    /// corresponding symbolic name can be found in /proc/pid/wchan.
    pub wchan: c_ulong,
    /// Number of pages swapped (not maintained).
    pub nswap: c_ulong,
    /// Cumulative nswap for child processes (not maintained).
    pub cnswap: c_ulong,
    /// Signal to be sent to parent when we die.
    pub exit_signal: c_int,
    /// CPU number last executed on.
    pub processor: c_int,
    /// Real-time scheduling priority, a number in the range 1 to 99 for
    /// processes scheduled under a real-time policy, or 0, for non-real-time
    /// processes (see sched_setscheduler(2)).
    pub rt_priority: c_uint,
    /// Scheduling policy (see sched_setscheduler(2)). Decode using the SCHED_*
    /// constants in linux/sched.h.
    pub policy: c_ulong,
    /// Aggregated block I/O delays, measured in clock ticks (centiseconds).
    pub delayacct_blkio_ticks: c_ulonglong,
    /// Guest time of the process (time spent running a virtual CPU for a guest
    /// operating system), measured in clock ticks (divide by
    /// sysconf(_SC_CLK_TCK)).
    pub guest_time: c_ulong,
    /// Guest time of the process's children, measured in clock ticks (divide by
    /// sysconf(_SC_CLK_TCK)).
    pub cguest_time: c_long,
    /// Address above which program initialized and uninitialized (BSS) data are
    /// placed.
    pub start_data: c_ulong,
    /// Address below which program initialized and uninitialized (BSS) data are
    /// placed.
    pub end_data: c_ulong,
    /// Address above which program heap can be expanded with brk(2).
    pub start_brk: c_ulong,
    /// Address above which program command-line arguments (argv) are placed.
    pub arg_start: c_ulong,
    /// Address below program command-line arguments (argv) are placed.
    pub arg_end: c_ulong,
    /// Address above which program environment is placed.
    pub env_start: c_ulong,
    /// Address below which program environment is placed.
    pub env_end: c_ulong,
    /// The thread's exit status in the form reported by waitpid(2).
    pub exit_code: c_ulong,
}

impl Stat {
    #[inline]
    pub fn from_content<B: AsRef<[u8]>>(content: B) -> Option<Self> {
        parse_content(content.as_ref())
    }

    pub fn from_reader<R: Read>(mut reader: R) -> io::Result<Self> {
        let mut content = {
            let mut content = Vec::with_capacity(512);
            reader.read_to_end(&mut content)?;
            content
        };

        if content.ends_with(b"\n") {
            content.pop();
        }
        if content.ends_with(b"\r") {
            content.pop();
        }
        content.shrink_to_fit();

        parse_content(&content)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Invalid process stat file"))
    }

    #[inline]
    pub fn from_file<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        Self::from_reader(File::open(path)?)
    }

    #[inline]
    pub fn current() -> io::Result<Self> {
        Self::from_file("/proc/self/stat")
    }
}

fn parse_content(mut content: &[u8]) -> Option<Stat> {
    use atoi::FromRadix10;

    fn parse_int<T: FromRadix10>(content: &[u8]) -> Option<(T, &[u8])> {
        let (res, len) = T::from_radix_10(content);
        if len == 0 || !matches!(content.get(len), Some(b' ')) {
            return None;
        }

        let content = unsafe { content.get_unchecked((len + 1)..) };
        Some((res, content))
    }

    fn parse_last_int<T: FromRadix10>(content: &[u8]) -> Option<T> {
        let (res, len) = T::from_radix_10(content);
        if len != content.len() {
            return None;
        }
        Some(res)
    }
    let mut stat = Stat::default();

    (stat.pid, content) = parse_int(content)?;
    {
        content = content.strip_prefix(b"(")?;
        let i = memchr::memrchr(b')', content)?;
        let comm = unsafe { content.get_unchecked(..i) };
        content = unsafe { content.get_unchecked((i + 1)..) };
        content = content.strip_prefix(b" ")?;
        if matches!(memchr::memchr(b'\0', comm), None) {
            stat.comm = unsafe { CString::from_vec_unchecked(comm.to_vec()) };
        } else {
            return None;
        }
    }
    {
        stat.state = match *content.first()? {
            b'R' => State::Running,
            b'S' => State::Sleeping,
            b'D' => State::Waiting,
            b'Z' => State::Zombie,
            b'T' if version!(<  2, 6, 33) => State::Stopped,
            b't' if version!(>= 2, 6, 33) => State::Tracing,
            b'W' if version!(<  2, 6, 0) => State::Paging,
            b'X' if version!(>= 2, 6, 0) => State::Dead,
            b'x' if version!(>= 2, 6, 33) && version!(<= 3, 13) => State::Dead,
            b'K' if version!(>= 2, 6, 33) && version!(<= 3, 13) => State::Wakekill,
            b'W' if version!(>= 2, 6, 33) && version!(<= 3, 13) => State::Waking,
            b'P' if version!(>= 3, 9) && version!(<= 3, 13) => State::Parked,
            b'I' if version!(>= 4, 14) => State::Idle,
            _ => return None,
        };
        content = unsafe { content.get_unchecked(1..) }.strip_prefix(b" ")?;
    }
    (stat.ppid, content) = parse_int(content)?;
    (stat.pgrp, content) = parse_int(content)?;
    (stat.session, content) = parse_int(content)?;
    (stat.tty_nr, content) = parse_int(content)?;
    (stat.tpgid, content) = parse_int(content)?;
    (stat.flags, content) = if version!(< 2, 6) {
        parse_int(content)?
    } else {
        let (f, c) = parse_int::<u32>(content)?;
        (f as c_ulong, c)
    };
    (stat.minflt, content) = parse_int(content)?;
    (stat.cminflt, content) = parse_int(content)?;
    (stat.majflt, content) = parse_int(content)?;
    (stat.cmajflt, content) = parse_int(content)?;
    (stat.utime, content) = parse_int(content)?;
    (stat.stime, content) = parse_int(content)?;
    (stat.cutime, content) = parse_int(content)?;
    (stat.cstime, content) = parse_int(content)?;
    (stat.priority, content) = parse_int(content)?;
    (stat.nice, content) = parse_int(content)?;
    (stat.num_threads, content) = parse_int(content)?;
    (stat.itrealvalue, content) = parse_int(content)?;
    (stat.start_time, content) = if version!(< 2, 6) {
        let (s, c) = parse_int::<c_ulong>(content)?;
        (s as c_ulonglong, c)
    } else {
        parse_int(content)?
    };
    (stat.vsize, content) = parse_int(content)?;
    (stat.rss, content) = parse_int(content)?;
    (stat.rsslim, content) = parse_int(content)?;
    (stat.startcode, content) = parse_int(content)?;
    (stat.endcode, content) = parse_int(content)?;
    (stat.startstack, content) = parse_int(content)?;
    (stat.kstkesp, content) = parse_int(content)?;
    (stat.kstkeip, content) = parse_int(content)?;
    (stat.signal, content) = parse_int(content)?;
    (stat.blocked, content) = parse_int(content)?;
    (stat.sigignore, content) = parse_int(content)?;
    (stat.sigcatch, content) = parse_int(content)?;
    (stat.wchan, content) = parse_int(content)?;
    (stat.nswap, content) = parse_int(content)?;

    if version!(< 2, 1, 22) {
        stat.cnswap = parse_last_int(content)?;
        return Some(stat);
    }
    (stat.cnswap, content) = parse_int(content)?;

    if version!(< 2, 2, 8) {
        stat.exit_signal = parse_last_int(content)?;
        return Some(stat);
    }
    (stat.exit_signal, content) = parse_int(content)?;

    if version!(< 2, 5, 19) {
        stat.processor = parse_last_int(content)?;
        return Some(stat);
    }
    (stat.processor, content) = parse_int(content)?;

    (stat.rt_priority, content) = parse_int(content)?;
    if version!(< 2, 6, 18) {
        stat.policy = parse_last_int(content)?;
        return Some(stat);
    }
    (stat.policy, content) = if version!(< 2, 6, 22) {
        parse_int(content)?
    } else {
        let (p, c) = parse_int::<c_uint>(content)?;
        (p as c_ulong, c)
    };

    if version!(< 2, 6, 24) {
        stat.delayacct_blkio_ticks = parse_last_int(content)?;
        return Some(stat);
    }
    (stat.delayacct_blkio_ticks, content) = parse_int(content)?;

    (stat.guest_time, content) = parse_int(content)?;
    if version!(< 3, 3) {
        stat.cguest_time = parse_last_int(content)?;
        return Some(stat);
    }
    (stat.cguest_time, content) = parse_int(content)?;

    (stat.start_data, content) = parse_int(content)?;
    (stat.end_data, content) = parse_int(content)?;
    if version!(< 3, 5) {
        stat.start_brk = parse_last_int(content)?;
        return Some(stat);
    }
    (stat.start_brk, content) = parse_int(content)?;

    (stat.arg_start, content) = parse_int(content)?;
    (stat.arg_end, content) = parse_int(content)?;
    (stat.env_start, content) = parse_int(content)?;
    (stat.env_end, content) = parse_int(content)?;
    stat.exit_code = parse_last_int(content)?;

    Some(stat)
}

#[cfg(test)]
mod tests {
    #[test]
    fn parse() {
        const STAT: &[u8] = b"43344 (cat) R 10751 43344 10751 34816 43344 4194304 125 0 0 0 0 0 0 0 20 0 1 0 603541 5767168 416 18446744073709551615 94256493502464 94256493517409 140731508568288 0 0 0 0 0 0 0 0 0 17 5 0 0 0 0 0 94256493529840 94256493531240 94256508383232 140731508575864 140731508575884 140731508575884 140731508580334 0";
        assert!(super::parse_content(STAT).is_some());
    }
}
