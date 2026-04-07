//! FUSE session and stream implementation.
//!
//! This reads FUSE requests directly from `/dev/fuse` and yields them as a `Stream`.
//! No libfuse C library is involved.

use std::collections::VecDeque;
use std::ffi::OsStr;
use std::io;
use std::mem;
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use anyhow::{Error, bail, format_err};
use futures::ready;
use futures::stream::{FusedStream, Stream};
use tokio::io::Interest;
use tokio::io::unix::AsyncFd;

use crate::mount;
use crate::protocol::{self, FuseInHeader, FuseInitIn, FuseInitOut, Opcode};
use crate::requests::{self, Request, RequestGuard};
use crate::sys::FuseFileInfo;
use crate::util::Stat;

/// Maximum write size negotiated with the kernel.
const MAX_WRITE: usize = 256 * 1024;
/// Read buffer size. The kernel requires at least:
///   max(FUSE_MIN_READ_BUFFER, sizeof(fuse_in_header) + sizeof(fuse_write_in) + max_write)
///   = max(8192, 40 + 40 + 262144) = 262224 bytes
const READ_BUF_SIZE: usize = MAX_WRITE + 4096; // 266240 ≥ 262224
const _: () = assert!(READ_BUF_SIZE >= protocol::FUSE_MIN_READ_BUFFER);

/// Bitflags tracking which operations are enabled.
#[derive(Clone, Copy, Default)]
struct EnabledOps {
    lookup: bool,
    forget: bool,
    getattr: bool,
    setattr: bool,
    statfs: bool,
    readdir: bool,
    readdirplus: bool,
    mkdir: bool,
    create: bool,
    mknod: bool,
    open: bool,
    release: bool,
    read: bool,
    write: bool,
    unlink: bool,
    rmdir: bool,
    rename: bool,
    readlink: bool,
    listxattr: bool,
    getxattr: bool,
}

pub struct FuseSessionBuilder {
    name: String,
    options: Vec<String>,
    ops: EnabledOps,
}

impl FuseSessionBuilder {
    pub fn options(mut self, option: &str) -> Self {
        self.options.push(option.to_string());
        self
    }

    pub fn options_os(self, option: &OsStr) -> Result<Self, Error> {
        let s = option
            .to_str()
            .ok_or_else(|| format_err!("option is not valid UTF-8"))?;
        Ok(self.options(s))
    }

    pub fn options_c(self, option: std::ffi::CString) -> Result<Self, Error> {
        let s = option
            .to_str()
            .map_err(|_| format_err!("option is not valid UTF-8"))?;
        Ok(self.options(s))
    }

    pub fn build(self) -> FuseSession {
        FuseSession {
            name: self.name,
            options: self.options,
            ops: self.ops,
        }
    }

    /// Enable `Readdir` requests.
    pub fn enable_readdir(mut self) -> Self {
        self.ops.readdir = true;
        self
    }

    /// Enables all of `ReaddirPlus`, `Lookup` and `Forget` requests.
    pub fn enable_readdirplus(mut self) -> Self {
        self.ops.readdirplus = true;
        self
    }

    /// Enable `Mkdir` requests.
    pub fn enable_mkdir(mut self) -> Self {
        self.ops.mkdir = true;
        self
    }

    /// Enable `Create`, `Open` and `Release` requests.
    pub fn enable_create(mut self) -> Self {
        self.ops.create = true;
        self.enable_open()
    }

    /// Enable `Mknod`.
    pub fn enable_mknod(mut self) -> Self {
        self.ops.mknod = true;
        self
    }

    /// Enable `Open` requests.
    pub fn enable_open(mut self) -> Self {
        self.ops.open = true;
        self.ops.release = true;
        self
    }

    /// Enable `Setattr` requests.
    pub fn enable_setattr(mut self) -> Self {
        self.ops.setattr = true;
        self
    }

    /// Enable `Statfs` requests.
    pub fn enable_statfs(mut self) -> Self {
        self.ops.statfs = true;
        self
    }

    /// Enable `Unlink` requests.
    pub fn enable_unlink(mut self) -> Self {
        self.ops.unlink = true;
        self
    }

    /// Enable `Rmdir` requests.
    pub fn enable_rmdir(mut self) -> Self {
        self.ops.rmdir = true;
        self
    }

    /// Enable `Rename` requests.
    pub fn enable_rename(mut self) -> Self {
        self.ops.rename = true;
        self
    }

    /// Enable `Read` requests.
    pub fn enable_read(mut self) -> Self {
        self.ops.read = true;
        self
    }

    /// Enable `Write` requests.
    pub fn enable_write(mut self) -> Self {
        self.ops.write = true;
        self
    }

    /// Enable `Readlink` requests.
    pub fn enable_readlink(mut self) -> Self {
        self.ops.readlink = true;
        self
    }

    /// Enable requests to list extended attributes.
    pub fn enable_read_xattr(mut self) -> Self {
        self.ops.listxattr = true;
        self.ops.getxattr = true;
        self
    }
}

pub struct FuseSession {
    name: String,
    options: Vec<String>,
    ops: EnabledOps,
}

impl FuseSession {
    /// Mount a FUSE filesystem at `mountpoint`.
    ///
    /// This function is **blocking** — it spawns `fusermount3` as a child process and waits for
    /// it to complete, then performs several synchronous syscalls (fcntl, socketpair, recvmsg)
    /// before returning. It also requires an active tokio runtime context, because the returned
    /// [`Fuse`] registers the FUSE fd with the tokio reactor via `AsyncFd`, which panics if no
    /// runtime handle is available.
    ///
    /// When calling from an async task, use [`mount_async`](Self::mount_async) instead to avoid
    /// blocking the runtime worker on the child-process wait.
    pub fn mount(self, mountpoint: &Path) -> Result<Fuse, Error> {
        let mountpoint_buf = mountpoint
            .canonicalize()
            .map_err(|e| format_err!("bad mount point: {e}"))?;

        let fuse_fd = mount::fuse_mount(&mountpoint_buf, &self.name, &self.options)
            .map_err(|e| format_err!("mount failed: {e}"))?;

        // SAFETY: fuse_fd is a valid, open file descriptor; F_GETFL/F_SETFL are valid fcntl ops.
        unsafe {
            let flags = libc::fcntl(fuse_fd.as_raw_fd(), libc::F_GETFL);
            if flags == -1 {
                bail!("fcntl(F_GETFL) failed: {}", io::Error::last_os_error());
            }
            let rc = libc::fcntl(fuse_fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK);
            if rc == -1 {
                bail!("fcntl(F_SETFL) failed: {}", io::Error::last_os_error());
            }
        }

        // Register the FUSE fd with tokio for both read-readiness and error events. The
        // error-event registration is what lets the reactor deliver EPOLLERR to us — which is
        // how the kernel signals that the FUSE connection has been torn down
        // (fusermount3 -u, /sys/fs/fuse/connections/N/abort, etc.).
        //
        // `poll_read_ready` only wakes on READABLE-direction events, so we spawn a short tokio
        // task that awaits `ready(Interest::ERROR)`. The task and `poll_next` share the same
        // `AsyncFd` via `Arc` — the two use disjoint waker mechanisms inside `ScheduledIo`
        // (fixed read waker slot vs. the async-path waiter linked list), so they don't clobber
        // each other. `poll_next` observes unmount by polling the watcher's `JoinHandle`
        // directly: completion (POLLERR observed) or abort from `Drop` both show up as a
        // ready result, which is all we need.
        let async_fd = Arc::new(
            AsyncFd::with_interest(Arc::new(fuse_fd), Interest::READABLE | Interest::ERROR)
                .map_err(|e| format_err!("failed to register fuse fd with tokio: {e}"))?,
        );

        let err_fd = Arc::clone(&async_fd);
        let err_watcher = tokio::spawn(async move {
            // The return value is intentionally ignored: any outcome — success, reactor
            // shutdown, or the task being aborted from `Fuse::drop` — means this task is
            // done, which is exactly the signal `poll_next` is looking for.
            let _ = err_fd.ready(Interest::ERROR).await;
        });

        Ok(Fuse {
            async_fd,
            mountpoint: mountpoint_buf,
            ops: self.ops,
            buf: Arc::new(vec![0u8; READ_BUF_SIZE]),
            pending: VecDeque::new(),
            init_done: false,
            finished: false,
            err_watcher,
        })
    }

    /// Async wrapper around [`mount`](Self::mount).
    ///
    /// `mount()` is blocking; this wrapper runs it on tokio's blocking thread pool via
    /// [`tokio::task::spawn_blocking`] so that calling it from an async task does not stall the
    /// runtime. The blocking thread inherits the current runtime handle, so `AsyncFd` registration
    /// inside `mount()` still works correctly.
    pub async fn mount_async(self, mountpoint: &Path) -> Result<Fuse, Error> {
        let mountpoint = mountpoint.to_owned();
        tokio::task::spawn_blocking(move || self.mount(&mountpoint))
            .await
            .map_err(|e| format_err!("mount task panicked: {e}"))?
    }
}

/// A mounted fuse file system.
///
/// This is a stream yielding `Request`s.
pub struct Fuse {
    async_fd: Arc<AsyncFd<Arc<OwnedFd>>>,
    mountpoint: PathBuf,
    ops: EnabledOps,
    buf: Arc<Vec<u8>>,
    pending: VecDeque<Request>,
    init_done: bool,
    finished: bool,
    /// Tokio task awaiting `ready(Interest::ERROR)` on the FUSE fd. Completion of this
    /// handle — whether the task ran to completion after POLLERR or was aborted by `Drop` —
    /// is the signal `poll_next` uses to terminate the stream.
    err_watcher: tokio::task::JoinHandle<()>,
}

impl Drop for Fuse {
    fn drop(&mut self) {
        // Cancel the POLLERR watcher task so it cannot outlive this struct and so it releases
        // its clone of the `Arc<AsyncFd>` promptly. `abort()` is non-blocking — it signals the
        // runtime to drop the task at its next await point.
        self.err_watcher.abort();
        // Fast path: a single `umount2(MNT_DETACH)` syscall. Returns instantly and does not
        // block. Succeeds whenever the caller holds CAP_SYS_ADMIN in the mount's user namespace
        // — in practice, every Proxmox deployment (which runs as root) always takes this path.
        match mount::umount2_detach(&self.mountpoint) {
            Ok(()) => {}
            // EPERM means the caller lacks CAP_SYS_ADMIN (unprivileged user in the init
            // namespace, mount was created via the setuid fusermount3 helper). Fall back to
            // the setuid helper itself — but on a detached thread, so `Drop` never blocks the
            // async runtime on the subprocess wait.
            Err(e) if e.raw_os_error() == Some(libc::EPERM) => {
                let mountpoint = std::mem::take(&mut self.mountpoint);
                std::thread::spawn(move || {
                    let _ = mount::fuse_unmount_via_helper(&mountpoint);
                });
            }
            // Any other error (EINVAL, ENOENT, EBUSY, …) means the mount is already gone or
            // the kernel refused for a reason the helper cannot work around either. Nothing
            // more we can usefully do from `Drop`.
            Err(_) => {}
        }
    }
}

impl Fuse {
    pub fn builder(name: &str) -> FuseSessionBuilder {
        FuseSessionBuilder {
            name: name.to_string(),
            options: Vec::new(),
            ops: EnabledOps {
                lookup: true,
                forget: true,
                getattr: true,
                ..Default::default()
            },
        }
    }

    /// Process one request from the buffer.
    ///
    /// Takes `buf` as a separate `Arc` to avoid borrow conflicts with `&mut self`.
    fn process_request(&mut self, buf: &Arc<Vec<u8>>, nbytes: usize) -> io::Result<()> {
        if nbytes < mem::size_of::<FuseInHeader>() {
            return Err(io::Error::other("short read from /dev/fuse"));
        }

        let header: FuseInHeader = read_body(&buf[..nbytes])?;

        if header.len as usize != nbytes {
            return Err(io::Error::other(format!(
                "FUSE header.len ({}) does not match read size ({})",
                header.len, nbytes,
            )));
        }

        let body = &buf[mem::size_of::<FuseInHeader>()..nbytes];

        if !self.init_done {
            return self.handle_init(&header, body);
        }

        let fd = Arc::clone(self.async_fd.get_ref());
        let guard = RequestGuard::new(header.unique, fd);

        let Some(opcode) = Opcode::from_u32(header.opcode) else {
            // Unknown opcode — the guard will reply ENOSYS on drop.
            return Ok(());
        };

        match opcode {
            Opcode::Destroy => {
                guard.disarm();
                self.finished = true;
            }
            Opcode::Interrupt => {
                // Let the guard's Drop send -ENOSYS. The kernel treats that as
                // "daemon cannot handle interrupts", sets fc->no_interrupt = 1
                // (see fs/fuse/dev.c:2231), and stops sending FUSE_INTERRUPT.
            }
            Opcode::Lookup if self.ops.lookup => {
                self.pending.push_back(Request::Lookup(requests::Lookup {
                    request: guard,
                    parent: header.nodeid,
                    file_name: protocol::name_from_bytes(body).to_owned(),
                }));
            }
            Opcode::Forget => {
                // FUSE_FORGET must never receive a reply — handle unconditionally.
                let forget_in: protocol::FuseForgetIn = read_body(body)?;
                if self.ops.forget {
                    self.pending.push_back(Request::Forget(requests::Forget {
                        request: guard,
                        inode: header.nodeid,
                        count: forget_in.nlookup,
                    }));
                } else {
                    guard.disarm();
                }
            }
            Opcode::BatchForget => {
                // FUSE_BATCH_FORGET must never receive a reply.
                guard.disarm();
                if self.ops.forget {
                    let batch_in: protocol::FuseBatchForgetIn = read_body(body)?;
                    let entries_start = mem::size_of::<protocol::FuseBatchForgetIn>();
                    let entry_size = mem::size_of::<protocol::FuseForgetOne>();
                    for i in 0..batch_in.count as usize {
                        let off = entries_start + i * entry_size;
                        if off + entry_size > body.len() {
                            break;
                        }
                        let entry: protocol::FuseForgetOne = read_body(&body[off..])?;
                        let fd = Arc::clone(self.async_fd.get_ref());
                        let forget_guard = RequestGuard::new(0, fd);
                        self.pending.push_back(Request::Forget(requests::Forget {
                            request: forget_guard,
                            inode: entry.nodeid,
                            count: entry.nlookup,
                        }));
                    }
                }
            }
            Opcode::Getattr if self.ops.getattr => {
                self.pending.push_back(Request::Getattr(requests::Getattr {
                    request: guard,
                    inode: header.nodeid,
                }));
            }
            Opcode::Setattr if self.ops.setattr => {
                let setattr_in: protocol::FuseSetattrIn = read_body(body)?;
                let valid = protocol::FattrFlags::from_bits_truncate(setattr_in.valid);
                let fh = valid
                    .contains(protocol::FattrFlags::FH)
                    .then_some(setattr_in.fh);
                self.pending.push_back(Request::Setattr(requests::Setattr {
                    request: guard,
                    inode: header.nodeid,
                    to_set: valid,
                    stat: Stat::from(setattr_in.to_stat()),
                    fh,
                }));
            }
            Opcode::Statfs if self.ops.statfs => {
                self.pending.push_back(Request::Statfs(requests::Statfs {
                    request: guard,
                    inode: header.nodeid,
                }));
            }
            Opcode::Readlink if self.ops.readlink => {
                self.pending.push_back(Request::Readlink(requests::Readlink {
                    request: guard,
                    inode: header.nodeid,
                }));
            }
            Opcode::Mknod if self.ops.mknod => {
                let mknod_in: protocol::FuseMknodIn = read_body(body)?;
                let file_name = protocol::name_after::<protocol::FuseMknodIn>(body)?.to_owned();
                self.pending.push_back(Request::Mknod(requests::Mknod {
                    request: guard,
                    parent: header.nodeid,
                    file_name,
                    mode: mknod_in.mode,
                    dev: mknod_in.rdev as libc::dev_t,
                }));
            }
            Opcode::Mkdir if self.ops.mkdir => {
                let mkdir_in: protocol::FuseMkdirIn = read_body(body)?;
                let dir_name = protocol::name_after::<protocol::FuseMkdirIn>(body)?.to_owned();
                self.pending.push_back(Request::Mkdir(requests::Mkdir {
                    request: guard,
                    parent: header.nodeid,
                    dir_name,
                    mode: mkdir_in.mode,
                }));
            }
            Opcode::Unlink if self.ops.unlink => {
                self.pending.push_back(Request::Unlink(requests::Unlink {
                    request: guard,
                    parent: header.nodeid,
                    file_name: protocol::name_from_bytes(body).to_owned(),
                }));
            }
            Opcode::Rmdir if self.ops.rmdir => {
                self.pending.push_back(Request::Rmdir(requests::Rmdir {
                    request: guard,
                    parent: header.nodeid,
                    dir_name: protocol::name_from_bytes(body).to_owned(),
                }));
            }
            Opcode::Rename2 if self.ops.rename => {
                let rename_in: protocol::FuseRename2In = read_body(body)?;
                let (name, new_name) = protocol::two_names_after::<protocol::FuseRename2In>(body)?;
                self.pending.push_back(Request::Rename(requests::Rename {
                    request: guard,
                    parent: header.nodeid,
                    name: name.to_owned(),
                    new_parent: rename_in.newdir,
                    new_name: new_name.to_owned(),
                    flags: rename_in.flags as libc::c_int,
                }));
            }
            Opcode::Open if self.ops.open => {
                let open_in: protocol::FuseOpenIn = read_body(body)?;
                self.pending.push_back(Request::Open(requests::Open {
                    request: guard,
                    inode: header.nodeid,
                    flags: open_in.flags as libc::c_int,
                    file_info: FuseFileInfo::default(),
                }));
            }
            Opcode::Release if self.ops.release => {
                let release_in: protocol::FuseReleaseIn = read_body(body)?;
                self.pending.push_back(Request::Release(requests::Release {
                    request: guard,
                    inode: header.nodeid,
                    fh: release_in.fh,
                    flags: release_in.flags as libc::c_int,
                }));
            }
            Opcode::Read if self.ops.read => {
                let read_in: protocol::FuseReadIn = read_body(body)?;
                self.pending.push_back(Request::Read(requests::Read {
                    request: guard,
                    inode: header.nodeid,
                    fh: read_in.fh,
                    size: read_in.size as usize,
                    offset: read_in.offset,
                }));
            }
            Opcode::Write if self.ops.write => {
                let write_in: protocol::FuseWriteIn = read_body(body)?;
                let data_offset =
                    mem::size_of::<FuseInHeader>() + mem::size_of::<protocol::FuseWriteIn>();
                let data_end = data_offset
                    .checked_add(write_in.size as usize)
                    .ok_or_else(|| io::Error::other("FUSE write size overflows"))?;
                if data_end > nbytes {
                    return Err(io::Error::other(format!(
                        "FUSE write claims {} data bytes but message is only {} bytes",
                        write_in.size, nbytes,
                    )));
                }
                self.pending.push_back(Request::Write(requests::Write::new(
                    guard,
                    header.nodeid,
                    write_in.fh,
                    data_offset,
                    write_in.size as usize,
                    write_in.offset,
                    Arc::clone(buf),
                )));
            }
            Opcode::Create if self.ops.create => {
                let create_in: protocol::FuseCreateIn = read_body(body)?;
                let file_name = protocol::name_after::<protocol::FuseCreateIn>(body)?.to_owned();
                self.pending.push_back(Request::Create(requests::Create {
                    request: guard,
                    parent: header.nodeid,
                    file_name,
                    mode: create_in.mode,
                    file_info: FuseFileInfo::default(),
                }));
            }
            Opcode::Readdir if self.ops.readdir => {
                let read_in: protocol::FuseReadIn = read_body(body)?;
                self.pending.push_back(Request::Readdir(requests::Readdir::new(
                    guard,
                    header.nodeid,
                    read_in.size as usize,
                    read_in.offset,
                )));
            }
            Opcode::Readdirplus if self.ops.readdirplus => {
                let read_in: protocol::FuseReadIn = read_body(body)?;
                self.pending.push_back(Request::ReaddirPlus(requests::ReaddirPlus::new(
                    guard,
                    header.nodeid,
                    read_in.size as usize,
                    read_in.offset,
                )));
            }
            Opcode::Listxattr if self.ops.listxattr => {
                let getxattr_in: protocol::FuseGetxattrIn = read_body(body)?;
                if getxattr_in.size == 0 {
                    self.pending.push_back(Request::ListXAttrSize(requests::ListXAttrSize {
                        request: guard,
                        inode: header.nodeid,
                    }));
                } else {
                    self.pending.push_back(Request::ListXAttr(requests::ListXAttr::new(
                        guard,
                        header.nodeid,
                        getxattr_in.size as usize,
                    )));
                }
            }
            Opcode::Getxattr if self.ops.getxattr => {
                let getxattr_in: protocol::FuseGetxattrIn = read_body(body)?;
                let attr_name = protocol::name_after::<protocol::FuseGetxattrIn>(body)?.to_owned();
                if getxattr_in.size == 0 {
                    self.pending.push_back(Request::GetXAttrSize(requests::GetXAttrSize {
                        request: guard,
                        inode: header.nodeid,
                        attr_name,
                    }));
                } else {
                    self.pending.push_back(Request::GetXAttr(requests::GetXAttr {
                        request: guard,
                        inode: header.nodeid,
                        attr_name,
                        size: getxattr_in.size as usize,
                    }));
                }
            }
            _ => {
                // Guard drop sends ENOSYS.
            }
        }

        Ok(())
    }

    fn handle_init(&mut self, header: &FuseInHeader, body: &[u8]) -> io::Result<()> {
        let opcode = Opcode::from_u32(header.opcode);
        if opcode != Some(Opcode::Init) {
            return Err(io::Error::other(format!(
                "expected FUSE_INIT, got opcode {}",
                header.opcode
            )));
        }

        let init_in: FuseInitIn = read_body(body)?;

        if init_in.major != protocol::FUSE_KERNEL_VERSION {
            return Err(io::Error::other(format!(
                "unsupported FUSE protocol major version: {} (expected {})",
                init_in.major,
                protocol::FUSE_KERNEL_VERSION
            )));
        }

        let init_out = negotiate_init(&init_in, &self.ops);

        let fd = self.async_fd.as_raw_fd();
        requests::send_reply(fd, header.unique, 0, requests::as_bytes(&init_out))?;

        self.init_done = true;
        Ok(())
    }
}

impl Stream for Fuse {
    type Item = io::Result<Request>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        loop {
            if let Some(request) = this.pending.pop_front() {
                return Poll::Ready(Some(Ok(request)));
            }

            if this.finished {
                return Poll::Ready(None);
            }

            // Check if the POLLERR watcher task has finished. `JoinHandle` is a `Future`, and
            // `is_ready()` covers both the normal case (task observed POLLERR and returned)
            // and the aborted case (yields `Err(JoinError)`) — either way, we terminate.
            // Setting `finished = true` below prevents us from polling the handle again.
            if Pin::new(&mut this.err_watcher).poll(cx).is_ready() {
                this.finished = true;
                return Poll::Ready(None);
            }

            let mut ready_guard = ready!(this.async_fd.poll_read_ready(cx))?;

            // If the buffer is still shared with outstanding Write requests (which borrow data
            // from it via Arc), allocate a fresh one instead of clobbering the in-flight data.
            if Arc::get_mut(&mut this.buf).is_none() {
                this.buf = Arc::new(vec![0u8; READ_BUF_SIZE]);
            }
            let buf = Arc::get_mut(&mut this.buf).unwrap();
            let buf_ptr = buf.as_mut_ptr() as *mut libc::c_void;
            let buf_len = buf.len();

            // `try_io` runs the closure and automatically calls `clear_ready()` on the guard if
            // the syscall returns `WouldBlock` (EAGAIN). This is the tokio-idiomatic way to
            // combine `AsyncFd` readiness notification with a direct syscall.
            let read_result = ready_guard.try_io(|inner| {
                let rc = unsafe { libc::read(inner.as_raw_fd(), buf_ptr, buf_len) };
                if rc < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(rc as usize)
                }
            });

            let nbytes = match read_result {
                // try_io detected EAGAIN and already called clear_ready; loop to re-poll.
                Err(_would_block) => continue,
                Ok(Ok(0)) => {
                    this.finished = true;
                    return Poll::Ready(None);
                }
                Ok(Ok(n)) => n,
                Ok(Err(err)) => match err.raw_os_error() {
                    // ENODEV: kernel closed the connection (normal fusermount3 -u).
                    // ECONNABORTED: connection aborted via /sys/fs/fuse/connections/<id>/abort.
                    Some(libc::ENODEV | libc::ECONNABORTED) => {
                        this.finished = true;
                        return Poll::Ready(None);
                    }
                    _ => return Poll::Ready(Some(Err(err))),
                },
            };

            let buf_ref = Arc::clone(&this.buf);
            drop(ready_guard);
            if let Err(err) = this.process_request(&buf_ref, nbytes) {
                return Poll::Ready(Some(Err(err)));
            }
        }
    }
}

impl FusedStream for Fuse {
    fn is_terminated(&self) -> bool {
        self.finished
    }
}

/// Build a `FuseInitOut` reply from the kernel's `FuseInitIn` and our enabled operations.
fn negotiate_init(init_in: &FuseInitIn, ops: &EnabledOps) -> FuseInitOut {
    use protocol::InitFlags;

    let minor = init_in.minor.min(protocol::FUSE_KERNEL_MINOR_VERSION);

    let mut flags = InitFlags::ASYNC_READ
        | InitFlags::BIG_WRITES
        | InitFlags::ATOMIC_O_TRUNC
        // We never handle FUSE_OPENDIR; advertise this so the kernel skips it
        // entirely for every directory open instead of burning one ENOSYS
        // round-trip per mount.
        | InitFlags::NO_OPENDIR_SUPPORT;
    if ops.readdirplus {
        flags |= InitFlags::DO_READDIRPLUS | InitFlags::READDIRPLUS_AUTO;
    }
    if !ops.open {
        // Daemon does not implement FUSE_OPEN: tell the kernel not to send it.
        flags |= InitFlags::NO_OPEN_SUPPORT;
    }

    let kernel_flags = InitFlags::from_bits_truncate(init_in.flags);
    let max_pages = if kernel_flags.contains(InitFlags::MAX_PAGES) {
        // SAFETY: _SC_PAGESIZE is a valid sysconf name; always succeeds on Linux.
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if page_size > 0 {
            flags |= InitFlags::MAX_PAGES;
            (MAX_WRITE / page_size as usize) as u16
        } else {
            0 // sysconf failed; skip MAX_PAGES negotiation
        }
    } else {
        0
    };

    let flags = flags & kernel_flags;

    FuseInitOut {
        major: protocol::FUSE_KERNEL_VERSION,
        minor,
        max_readahead: init_in.max_readahead,
        flags: flags.bits(),
        max_background: 0,
        congestion_threshold: 0,
        max_write: MAX_WRITE as u32,
        time_gran: 1,
        max_pages,
        map_alignment: 0,
        flags2: 0,
        max_stack_depth: 0,
        request_timeout: 0,
        unused: [0; 11],
    }
}

/// Read a `repr(C)` struct from a byte buffer.
fn read_body<T: Copy>(body: &[u8]) -> io::Result<T> {
    if body.len() < mem::size_of::<T>() {
        return Err(io::Error::other(format!(
            "truncated FUSE message: expected {} bytes, got {}",
            mem::size_of::<T>(),
            body.len(),
        )));
    }
    // SAFETY: we verified body.len() >= size_of::<T>() above; read_unaligned handles
    // the fact that body.as_ptr() may not be aligned for T.
    Ok(unsafe { (body.as_ptr() as *const T).read_unaligned() })
}

