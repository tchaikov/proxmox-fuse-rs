//! Mount and unmount a FUSE filesystem.
//!
//! Both mount and unmount use the same hybrid strategy as libfuse3: try a direct syscall first
//! (which requires `CAP_SYS_ADMIN` in the mount's user namespace — i.e. root in the init
//! namespace, the Proxmox production configuration) and fall back to the setuid `fusermount3`
//! helper only if the kernel rejects the direct call with `EPERM`.
//!
//! **Mount**: open `/dev/fuse`, build the `fd=N,rootmode=…,user_id=…,group_id=…` option
//! string, then call `mount(2)` directly. On `EPERM`, fall back to spawning `fusermount3` and
//! receiving its `/dev/fuse` fd via `SCM_RIGHTS`.
//!
//! **Unmount**: call `umount2(path, MNT_DETACH)` directly. On `EPERM`, spawn `fusermount3 -u`.
//! `MNT_DETACH` is a lazy unmount that returns instantly, which is why the fast path is safe
//! to call from `Drop`.

use std::ffi::CString;
use std::io;
use std::mem;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::process::Command;

/// Mount a FUSE filesystem at `mountpoint` with the given `fsname` and `options`.
///
/// Returns the `/dev/fuse` file descriptor for communicating with the kernel.
///
/// Tries the direct `mount(2)` syscall first, and falls back to the `fusermount3` setuid helper
/// only if the kernel rejects the direct call with `EPERM` (unprivileged caller). The direct
/// path avoids a subprocess fork/exec/wait and the socketpair/`SCM_RIGHTS` fd dance entirely,
/// which matters for the Proxmox use case where the daemon runs as root.
pub fn fuse_mount(mountpoint: &Path, fsname: &str, options: &[String]) -> io::Result<OwnedFd> {
    match fuse_mount_direct(mountpoint, fsname, options) {
        Ok(fd) => Ok(fd),
        // Only EPERM means "kernel refused this unprivileged mount"; any other errno is a real
        // failure that fusermount3 cannot fix either.
        Err(e) if e.raw_os_error() == Some(libc::EPERM) => {
            fuse_mount_via_helper(mountpoint, fsname, options)
        }
        Err(e) => Err(e),
    }
}

/// Direct `mount(2)` syscall. Opens `/dev/fuse`, builds the FUSE-specific option string, and
/// calls the syscall. Returns `EPERM` if the caller lacks `CAP_SYS_ADMIN`.
fn fuse_mount_direct(
    mountpoint: &Path,
    fsname: &str,
    options: &[String],
) -> io::Result<OwnedFd> {
    let c_mountpoint = CString::new(mountpoint.as_os_str().as_bytes())
        .map_err(|_| io::Error::other("mountpoint path contains NUL byte"))?;

    // The kernel needs the mountpoint's file-type bits so it can synthesise attributes for the
    // root inode. For a normal directory mount this is S_IFDIR (040000 octal).
    // SAFETY: zeroed memory is a valid initial state for libc::stat.
    let mut stbuf: libc::stat = unsafe { mem::zeroed() };
    // SAFETY: c_mountpoint is a valid NUL-terminated C string, stbuf is a valid out-pointer.
    if unsafe { libc::stat(c_mountpoint.as_ptr(), &mut stbuf) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let rootmode = stbuf.st_mode & libc::S_IFMT;

    // Open /dev/fuse. Wrap in OwnedFd immediately so the fd is closed automatically on any
    // subsequent error return.
    // SAFETY: c"/dev/fuse" is a valid path; O_RDWR|O_CLOEXEC are valid flags.
    let fd = unsafe { libc::open(c"/dev/fuse".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fd is a valid, newly-opened file descriptor (checked above).
    let owned_fd = unsafe { OwnedFd::from_raw_fd(fd) };

    // Build the FUSE mount option string. `fd`, `rootmode`, `user_id`, `group_id` are mandatory;
    // user-supplied options are appended verbatim.
    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };
    let mut opts_str = format!("fd={fd},rootmode={rootmode:o},user_id={uid},group_id={gid}");
    for extra in options {
        opts_str.push(',');
        opts_str.push_str(extra);
    }
    let c_opts = CString::new(opts_str)
        .map_err(|_| io::Error::other("mount options contain NUL byte"))?;

    // `source` is the filesystem name shown in /proc/mounts; libfuse passes the fsname here.
    let c_source = CString::new(fsname)
        .map_err(|_| io::Error::other("fsname contains NUL byte"))?;

    // SAFETY: all pointers are valid NUL-terminated C strings; flags are valid mount flags.
    let rc = unsafe {
        libc::mount(
            c_source.as_ptr(),
            c_mountpoint.as_ptr(),
            c"fuse".as_ptr(),
            libc::MS_NOSUID | libc::MS_NODEV,
            c_opts.as_ptr() as *const libc::c_void,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(owned_fd)
}

/// Fallback mount via the setuid `fusermount3` helper. Spawns the helper, passes a socketpair
/// fd for it to send `/dev/fuse` back through via `SCM_RIGHTS`, and receives the fd.
///
/// This **blocks** on the child process. Callers from async context should wrap this in
/// `tokio::task::spawn_blocking`.
fn fuse_mount_via_helper(
    mountpoint: &Path,
    fsname: &str,
    options: &[String],
) -> io::Result<OwnedFd> {
    let (sock_parent, sock_child) = unix_socketpair()?;

    let mut opt_parts = vec![format!("fsname={fsname}")];
    opt_parts.extend_from_slice(options);
    let opts = opt_parts.join(",");

    let status = Command::new("fusermount3")
        .arg("-o")
        .arg(&opts)
        .arg("--")
        .arg(mountpoint)
        .env("_FUSE_COMMFD", sock_child.as_raw_fd().to_string())
        .spawn()
        .map_err(|e| io::Error::other(format!("failed to execute fusermount3: {e}")))?
        .wait()
        .map_err(|e| io::Error::other(format!("failed to wait for fusermount3: {e}")))?;

    drop(sock_child);

    if !status.success() {
        return Err(io::Error::other(format!("fusermount3 failed with {status}")));
    }

    recv_fd(&sock_parent)
}

/// Direct `umount2(path, MNT_DETACH)` syscall.
///
/// Succeeds when the caller holds `CAP_SYS_ADMIN` in the mount's user namespace — that is,
/// any root caller in the init namespace, or a privileged caller in an unprivileged user
/// namespace where the mount was created. Returns `EPERM` for everyone else, including
/// unprivileged users whose mount was created via the setuid `fusermount3` helper.
///
/// MNT_DETACH is a lazy unmount: it detaches the filesystem from the mount tree immediately
/// and lets the kernel clean up asynchronously when the last reference drops. The syscall
/// returns instantly, which is why this is safe to call from `Drop`.
pub(crate) fn umount2_detach(mountpoint: &Path) -> io::Result<()> {
    let c_path = CString::new(mountpoint.as_os_str().as_bytes())
        .map_err(|_| io::Error::other("mountpoint path contains NUL byte"))?;
    // SAFETY: c_path is a valid NUL-terminated C string; MNT_DETACH is a valid flag.
    let rc = unsafe { libc::umount2(c_path.as_ptr(), libc::MNT_DETACH) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Fallback unmount via the setuid `fusermount3 -u` helper.
///
/// This **blocks** waiting for the child process to exit. Callers from async context must run it
/// on a blocking thread (e.g. via [`std::thread::spawn`]) to avoid stalling the runtime.
pub(crate) fn fuse_unmount_via_helper(mountpoint: &Path) -> io::Result<()> {
    let status = Command::new("fusermount3")
        .arg("-u")
        .arg("-q")
        .arg("-z")
        .arg("--")
        .arg(mountpoint)
        .status()
        .map_err(|e| io::Error::other(format!("failed to execute fusermount3 -u: {e}")))?;

    if !status.success() {
        return Err(io::Error::other(format!(
            "fusermount3 -u failed with {status}"
        )));
    }
    Ok(())
}

/// Create a Unix socket pair.
///
/// The parent (fds[0]) gets `SOCK_CLOEXEC` so it is not inherited by the
/// fusermount3 child process. The child (fds[1]) intentionally has no
/// CLOEXEC — it must survive exec so fusermount3 can write back the fd.
fn unix_socketpair() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0i32; 2];
    // SAFETY: fds is a valid out-pointer for two file descriptors.
    let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: socketpair succeeded; fds[0] and fds[1] are valid, newly-created file descriptors.
    let (parent, child) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
    // Set CLOEXEC on the parent socket only — the child fd must survive exec into fusermount3.
    // SAFETY: parent is a valid fd; F_SETFD + FD_CLOEXEC are valid arguments.
    let rc = unsafe { libc::fcntl(parent.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((parent, child))
}

/// Receive a file descriptor via `SCM_RIGHTS` on a Unix socket.
fn recv_fd(sock: &OwnedFd) -> io::Result<OwnedFd> {
    let sock_fd = sock.as_raw_fd();

    // Ancillary buffer for one fd via SCM_RIGHTS; must be aligned for cmsghdr.
    const CMSG_BUF_SIZE: usize =
        unsafe { libc::CMSG_SPACE(std::mem::size_of::<i32>() as u32) } as usize;
    #[repr(C, align(8))]
    struct CmsgBuf([u8; CMSG_BUF_SIZE]);
    let mut cmsg_buf = CmsgBuf([0u8; CMSG_BUF_SIZE]);
    let mut dummy_buf = [0u8; 1];

    let mut iov = libc::iovec {
        iov_base: dummy_buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: dummy_buf.len(),
    };

    // SAFETY: zeroed memory is a valid initial state for msghdr.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.0.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = cmsg_buf.0.len() as _;

    // SAFETY: msg is properly initialised with valid iov/control pointers and lengths.
    let rc = unsafe { libc::recvmsg(sock_fd, &mut msg, libc::MSG_CMSG_CLOEXEC) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: msg was populated by a successful recvmsg; CMSG_FIRSTHDR reads the msg header.
    let cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
    if cmsg.is_null() {
        return Err(io::Error::other(
            "fusermount3 did not send a file descriptor",
        ));
    }

    // SAFETY: cmsg is non-null (checked above) and points into our stack-allocated cmsg_buf.
    let cmsg = unsafe { &*cmsg };
    if cmsg.cmsg_level != libc::SOL_SOCKET || cmsg.cmsg_type != libc::SCM_RIGHTS {
        return Err(io::Error::other(
            "unexpected ancillary data from fusermount3",
        ));
    }

    // SAFETY: we verified cmsg_level/cmsg_type are SCM_RIGHTS, so CMSG_DATA points to an i32 fd.
    let fd = unsafe { *(libc::CMSG_DATA(cmsg) as *const i32) };
    if fd < 0 {
        return Err(io::Error::other(
            "fusermount3 sent an invalid file descriptor",
        ));
    }

    // SAFETY: fd is a valid file descriptor received via SCM_RIGHTS (checked above).
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}
