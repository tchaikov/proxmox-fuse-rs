//! The bigger part of the public API is about which requests we're handling.
//!
//! Reply functions write directly to the FUSE device file descriptor.

use std::ffi::{CStr, CString, OsStr, OsString};
use std::io;
use std::io::IoSlice;
use std::mem;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::sync::Arc;
use std::time::Duration;

use crate::protocol::{
    self, FuseAttrOut, FuseGetxattrOut, FuseOpenOut, FuseOutHeader, FuseWriteOut,
};
use crate::sys::{self, ReplyBufState};
use crate::util::Stat;

pub use crate::sys::FuseFileInfo;

/// Error type for reply methods where cancellation has semantic consequences.
///
/// When the kernel cancels a FUSE request (via `FUSE_INTERRUPT`), the reply write returns
/// `-ENOENT`. For most requests this is harmless, but for `Open`, `Create`, and `Lookup` it means:
///
/// - `Open`/`Create`: No `Release` event will arrive, so any allocated file handle must be cleaned
///   up immediately.
/// - `Lookup`: The lookup count was NOT incremented, so the caller must not expect a corresponding
///   `Forget`.
#[derive(Debug)]
pub enum ReplyError {
    /// The kernel cancelled the request before the reply could be delivered.
    Cancelled,
    /// An I/O error occurred while sending the reply.
    Io(io::Error),
}

impl std::fmt::Display for ReplyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReplyError::Cancelled => f.write_str("request was cancelled"),
            ReplyError::Io(err) => write!(f, "reply I/O error: {err}"),
        }
    }
}

impl std::error::Error for ReplyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ReplyError::Cancelled => None,
            ReplyError::Io(err) => Some(err),
        }
    }
}

impl From<io::Error> for ReplyError {
    fn from(err: io::Error) -> Self {
        ReplyError::Io(err)
    }
}

/// Shared reference to the FUSE device fd used for sending replies.
pub(crate) type FuseFdRef = Arc<std::os::fd::OwnedFd>;

#[derive(Debug)]
pub struct RequestGuard {
    pub(crate) unique: u64,
    pub(crate) fd: FuseFdRef,
}

impl RequestGuard {
    pub(crate) fn new(unique: u64, fd: FuseFdRef) -> Self {
        Self { unique, fd }
    }

    /// Consume the request and do not trigger the automatic `ENOSYS` response.
    pub fn disarm(mut self) {
        // The FUSE kernel protocol guarantees unique IDs are always non-zero,
        // so 0 is a safe sentinel meaning "already replied / disarmed".
        self.unique = 0;
    }
}

impl Drop for RequestGuard {
    fn drop(&mut self) {
        // unique == 0 means the request was already replied to or explicitly disarmed.
        if self.unique != 0 {
            let _ = send_error_reply(self.fd.as_raw_fd(), self.unique, libc::ENOSYS);
        }
    }
}

/// Send a reply consisting of a header plus a single contiguous body to the FUSE fd.
///
/// Writes to `/dev/fuse` are atomic: the kernel processes one complete message per `writev`
/// call and returns the full length or an error, so partial writes cannot occur and we do not
/// need to retry.
pub(crate) fn send_reply(fd: i32, unique: u64, error: i32, data: &[u8]) -> io::Result<()> {
    let len = u32::try_from(mem::size_of::<FuseOutHeader>() + data.len())
        .map_err(|_| io::Error::other("FUSE reply exceeds u32::MAX"))?;
    let header = FuseOutHeader { len, error, unique };

    let iov = [IoSlice::new(as_bytes(&header)), IoSlice::new(data)];

    // SAFETY: `iov` points to valid IoSlice elements whose backing memory (`header` and
    // `data`) is alive for the duration of the call.
    let rc = unsafe { libc::writev(fd, iov.as_ptr() as *const libc::iovec, iov.len() as i32) };
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Send a reply with multiple data segments. Used by `Create::reply` (entry_out + open_out)
/// and `Read::reply_vectored`.
fn send_reply_vectored(
    fd: i32,
    unique: u64,
    data_slices: &[IoSlice<'_>],
    data_len: usize,
) -> io::Result<()> {
    let len = u32::try_from(mem::size_of::<FuseOutHeader>() + data_len)
        .map_err(|_| io::Error::other("FUSE reply exceeds u32::MAX"))?;
    let header = FuseOutHeader {
        len,
        error: 0,
        unique,
    };

    let mut iov = Vec::with_capacity(1 + data_slices.len());
    iov.push(IoSlice::new(as_bytes(&header)));
    iov.extend_from_slice(data_slices);

    // SAFETY: `iov` points to valid IoSlice elements; the header lives on the stack and
    // the data_slices are caller-provided references valid for the duration of the call.
    let rc = unsafe { libc::writev(fd, iov.as_ptr() as *const libc::iovec, iov.len() as i32) };
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn send_error_reply(fd: i32, unique: u64, errno: i32) -> io::Result<()> {
    send_reply(fd, unique, -errno, &[])
}

/// Map a reply I/O result to a `ReplyError`, detecting cancellation.
///
/// The FUSE kernel returns `ENOENT` when a request was interrupted before the reply
/// could be delivered.
fn cancellable(result: io::Result<()>) -> Result<(), ReplyError> {
    match result {
        Ok(()) => Ok(()),
        Err(err) if err.raw_os_error() == Some(libc::ENOENT) => Err(ReplyError::Cancelled),
        Err(err) => Err(ReplyError::Io(err)),
    }
}

fn name_to_cstring(name: &OsStr) -> io::Result<CString> {
    CString::new(name.as_bytes())
        .map_err(|_| io::Error::other("tried to reply with invalid file name"))
}

/// Reinterpret a `repr(C)` struct as a byte slice.
///
/// # Safety contract
///
/// This is only sound if `T` has no padding bytes that might be uninitialised. All protocol
/// structs in this crate satisfy this: they are `#[repr(C)]` with explicit `padding` or `dummy`
/// fields initialised to zero.
pub(crate) fn as_bytes<T>(val: &T) -> &[u8] {
    // SAFETY: `val` is a valid `T` reference; `repr(C)` guarantees a well-defined layout;
    // the resulting slice borrows `val` for `'_` so it cannot outlive the source.
    unsafe { std::slice::from_raw_parts(val as *const T as *const u8, mem::size_of::<T>()) }
}

fn reply_err(request: RequestGuard, errno: libc::c_int) -> io::Result<()> {
    let fd = request.fd.as_raw_fd();
    let unique = request.unique;
    request.disarm();
    send_error_reply(fd, unique, errno)
}

fn reply_ok(request: &mut RequestGuard, data: &[u8]) -> io::Result<()> {
    let fd = request.fd.as_raw_fd();
    let unique = request.unique;
    send_reply(fd, unique, 0, data)?;
    request.unique = 0; // disarm
    Ok(())
}

fn reply_xattr_size(request: &mut RequestGuard, size: usize) -> io::Result<()> {
    let size = u32::try_from(size).map_err(|_| io::Error::other("xattr size exceeds u32::MAX"))?;
    let out = FuseGetxattrOut { size, padding: 0 };
    reply_ok(request, as_bytes(&out))
}

fn reply_entry(request: &mut RequestGuard, entry: &sys::EntryParam) -> io::Result<()> {
    let entry_out = protocol::entry_out_from_param(entry);
    reply_ok(request, as_bytes(&entry_out))
}

fn reply_attr(request: &mut RequestGuard, stat: &libc::stat, timeout: f64) -> io::Result<()> {
    let (attr_valid, attr_valid_nsec) = protocol::split_timeout(timeout);
    let attr_out = FuseAttrOut {
        attr_valid,
        attr_valid_nsec,
        dummy: 0,
        attr: protocol::FuseAttr::from_stat(stat),
    };
    reply_ok(request, as_bytes(&attr_out))
}

fn reply_ok_cancellable(request: &mut RequestGuard, data: &[u8]) -> Result<(), ReplyError> {
    let fd = request.fd.as_raw_fd();
    let unique = request.unique;
    let result = cancellable(send_reply(fd, unique, 0, data));
    match &result {
        Ok(()) | Err(ReplyError::Cancelled) => request.unique = 0, // disarm
        Err(ReplyError::Io(_)) => {}
    }
    result
}

/// Implement `FuseRequest` for a request struct that stores its guard in a `request` field.
/// Most request types share this identical `fail` implementation.
macro_rules! impl_fuse_request {
    ($($ty:ty),+ $(,)?) => { $(
        impl FuseRequest for $ty {
            fn fail(self, errno: libc::c_int) -> io::Result<()> {
                reply_err(self.request, errno)
            }
        }
    )+ };
}

impl_fuse_request!(
    Lookup, Getattr, Setattr, Statfs, Mkdir, Create, Mknod, Open, Release, Read, Write, Unlink,
    Rmdir, Rename, Readlink, ListXAttrSize, ListXAttr, GetXAttrSize, GetXAttr,
);

/// Helper trait to easily provide the fail method for all the request types within the `Request`
/// enum even after they have been moved out of the enum, without requiring the exact type.
pub trait FuseRequest: Sized {
    /// Send an error reply.
    fn fail(self, errno: libc::c_int) -> io::Result<()>;

    /// Convenience method to use an `io::Error` as a response.
    fn io_fail(self, error: io::Error) -> io::Result<()> {
        self.fail(error.raw_os_error().unwrap_or(libc::EIO))
    }
}

#[derive(Debug)]
#[non_exhaustive]
pub enum Request {
    Lookup(Lookup),
    Forget(Forget),
    Getattr(Getattr),
    Setattr(Setattr),
    Statfs(Statfs),
    Readdir(Readdir),
    ReaddirPlus(ReaddirPlus),
    Mkdir(Mkdir),
    Create(Create),
    Mknod(Mknod),
    Open(Open),
    Release(Release),
    Read(Read),
    Unlink(Unlink),
    Rmdir(Rmdir),
    Write(Write),
    Readlink(Readlink),
    Rename(Rename),
    ListXAttrSize(ListXAttrSize),
    ListXAttr(ListXAttr),
    GetXAttrSize(GetXAttrSize),
    GetXAttr(GetXAttr),
}

impl FuseRequest for Request {
    fn fail(self, errno: libc::c_int) -> io::Result<()> {
        // Forget never gets a reply — the Forget request's own Drop handles disarming.
        // Every other variant forwards to the inner type's `fail`.
        macro_rules! forward {
            ($($variant:ident),+ $(,)?) => {
                match self {
                    Request::Forget(r) => r.fail(errno),
                    $(Request::$variant(r) => r.fail(errno),)+
                }
            };
        }
        forward!(
            Lookup, Getattr, Setattr, Statfs, Readdir, ReaddirPlus, Mkdir, Create, Mknod, Open,
            Release, Read, Unlink, Rmdir, Write, Readlink, Rename, ListXAttrSize, ListXAttr,
            GetXAttrSize, GetXAttr,
        )
    }
}

/// A lookup for an entry in a directory. This should increase the lookup count for the inode,
/// as from then on the kernel will refer to the looked-up entry only via the inode..
#[derive(Debug)]
pub struct Lookup {
    pub(crate) request: RequestGuard,
    pub parent: u64,
    pub file_name: OsString,
}

impl Lookup {
    pub fn reply(mut self, entry: &sys::EntryParam) -> Result<(), ReplyError> {
        let entry_out = protocol::entry_out_from_param(entry);
        reply_ok_cancellable(&mut self.request, as_bytes(&entry_out))
    }
}

/// Forget references (lookup count) for an inode. Once an inode reaches a lookup count of zero,
/// the kernel will not refer to the inode anymore, meaning any cached information to access it may
/// be released.
#[derive(Debug)]
pub struct Forget {
    pub(crate) request: RequestGuard,
    pub inode: u64,
    pub count: u64,
}

impl Drop for Forget {
    fn drop(&mut self) {
        // FUSE_FORGET must never receive a reply — disarm the guard so
        // RequestGuard::drop does not send ENOSYS if the consumer drops
        // without calling reply().
        self.request.unique = 0;
    }
}

impl FuseRequest for Forget {
    /// Forget cannot fail.
    fn fail(self, _errno: libc::c_int) -> io::Result<()> {
        Ok(())
    }
}

impl Forget {
    pub fn reply(self) {
        // FUSE_FORGET sends no kernel reply — Drop handles disarming.
    }
}

/// This is the equivalent of a `stat` call.
///
/// The inode is already known, so no changes to the lookup count occur.
#[derive(Debug)]
pub struct Getattr {
    pub(crate) request: RequestGuard,
    pub inode: u64,
}

impl Getattr {
    /// Send a reply for a `Getattr` request.
    pub fn reply(mut self, stat: &libc::stat, timeout: f64) -> io::Result<()> {
        reply_attr(&mut self.request, stat, timeout)
    }
}

/// Get filesystem statistics.
///
/// This is the equivalent of a `statfs` call.
#[derive(Debug)]
pub struct Statfs {
    pub(crate) request: RequestGuard,
    pub inode: u64,
}

impl Statfs {
    /// Send a reply for a `Statfs` request.
    pub fn reply(mut self, stbuf: &libc::statvfs) -> io::Result<()> {
        let kstatfs = protocol::FuseKstatfs::from_statvfs(stbuf);
        reply_ok(&mut self.request, as_bytes(&kstatfs))
    }
}

/// Common structure and boilerplate shared by `Readdir` and `ReaddirPlus`.
///
/// Both types hold an `Option<RequestGuard>` and an `Option<ReplyBuf>`, and share identical
/// `Drop`, `FuseRequest`, `new()`, and `reply()` implementations.
macro_rules! impl_readdir_common {
    ($(#[$attr:meta])* $name:ident) => {
        $(#[$attr])*
        #[derive(Debug)]
        pub struct $name {
            pub(crate) request: Option<RequestGuard>,
            pub inode: u64,
            pub offset: u64,
            reply_buffer: Option<sys::ReplyBuf>,
        }

        impl Drop for $name {
            fn drop(&mut self) {
                if self.reply_buffer.is_some() {
                    let _ = reply_err(self.request.take().unwrap(), libc::EIO);
                }
            }
        }

        impl FuseRequest for $name {
            fn fail(mut self, errno: libc::c_int) -> io::Result<()> {
                self.reply_buffer = None;
                reply_err(self.request.take().unwrap(), errno)
            }
        }

        impl $name {
            pub(crate) fn new(
                request: RequestGuard,
                inode: u64,
                size: usize,
                offset: u64,
            ) -> Self {
                Self {
                    request: Some(request),
                    inode,
                    offset,
                    reply_buffer: Some(sys::ReplyBuf::new(size)),
                }
            }

            /// Send a successful reply. This also works if no entries have been added via
            /// `add_entry`, indicating an empty directory without `.` or `..` present.
            pub fn reply(mut self) -> io::Result<()> {
                let mut request = self.request.take().unwrap();
                let buf = self.reply_buffer.take().unwrap();
                reply_ok(&mut request, buf.filled_data())
            }
        }
    };
}

impl_readdir_common!(
    /// Get the contents of a directory without changing any lookup counts. (Contrary to
    /// `ReaddirPlus`).
    Readdir
);

impl Readdir {
    /// Add a reply entry. Note that unless you also consume the `Readdir` object with a call to
    /// the `reply()` method, this will produce an `EIO` error.
    pub fn add_entry(
        &mut self,
        name: &OsStr,
        stat: &libc::stat,
        next: u64,
    ) -> io::Result<ReplyBufState> {
        let name = name_to_cstring(name)?;

        Ok(self
            .reply_buffer
            .as_mut()
            .unwrap()
            .add_readdir(&name, stat, next))
    }
}

impl_readdir_common!(
    /// Lookup all the contents of a directory. On success, the lookup count of all the returned
    /// entries should be increased by 1.
    ReaddirPlus
);

impl ReaddirPlus {
    /// Add a reply entry. Note that unless you also consume the `ReaddirPlus` object with a call
    /// to the `reply()` method, this will produce an `EIO` error.
    pub fn add_entry(
        &mut self,
        name: &OsStr,
        stat: &libc::stat,
        next: u64,
        generation: u64,
        attr_timeout: f64,
        entry_timeout: f64,
    ) -> io::Result<ReplyBufState> {
        let name = name_to_cstring(name)?;

        let entry = sys::EntryParam {
            inode: stat.st_ino,
            generation,
            attr: *stat,
            attr_timeout,
            entry_timeout,
        };

        Ok(self
            .reply_buffer
            .as_mut()
            .unwrap()
            .add_readdir_plus(&name, &entry, next))
    }
}

/// Create a new directory with a lookup count of 1.
#[derive(Debug)]
pub struct Mkdir {
    pub(crate) request: RequestGuard,
    pub parent: u64,
    pub dir_name: OsString,
    pub mode: libc::mode_t,
}

impl Mkdir {
    pub fn reply(mut self, entry: &sys::EntryParam) -> io::Result<()> {
        reply_entry(&mut self.request, entry)
    }
}

/// Create a new file with a lookup count of 1.
#[derive(Debug)]
pub struct Create {
    pub(crate) request: RequestGuard,
    pub parent: u64,
    pub file_name: OsString,
    pub mode: libc::mode_t,
    pub file_info: FuseFileInfo,
}

impl Create {
    /// The `fh` provided here will be available in later requests for this file handle.
    ///
    /// If this returns `ReplyError::Cancelled`, no `Release` event will arrive for this file
    /// handle. The caller must clean up any resources associated with `fh` immediately.
    pub fn reply(self, entry: &sys::EntryParam, fh: u64) -> Result<(), ReplyError> {
        let entry_out = protocol::entry_out_from_param(entry);
        let open_out = FuseOpenOut {
            fh,
            open_flags: self.file_info.open_flags_out().bits(),
            backing_id: 0,
        };
        let data_len = mem::size_of_val(&entry_out) + mem::size_of_val(&open_out);
        let fd = self.request.fd.as_raw_fd();
        let unique = self.request.unique;
        self.request.disarm();
        let slices = [
            IoSlice::new(as_bytes(&entry_out)),
            IoSlice::new(as_bytes(&open_out)),
        ];
        cancellable(send_reply_vectored(fd, unique, &slices, data_len))
    }
}

/// Create a new node (file or device) with a lookup count of 1.
#[derive(Debug)]
pub struct Mknod {
    pub(crate) request: RequestGuard,
    pub parent: u64,
    pub file_name: OsString,
    pub mode: libc::mode_t,
    pub dev: libc::dev_t,
}

impl Mknod {
    /// The lookup count should be bumped by this reply.
    pub fn reply(mut self, entry: &sys::EntryParam) -> io::Result<()> {
        reply_entry(&mut self.request, entry)
    }
}

/// Open a file. This counts as one reference to the file and can be tracked separately or as part
/// of the lookup count. If dealing with opened files requires a kind of state, the `fh` parameter
/// on the `reply` method should point to that state, as it will be included in all requests
/// related to this handle.
#[derive(Debug)]
pub struct Open {
    pub(crate) request: RequestGuard,
    pub inode: u64,
    pub flags: libc::c_int,

    /// This can be used to set flags like `direct_io` or `writecache`...
    pub file_info: FuseFileInfo,
}

impl Open {
    /// The `fh` provided here will be available in later requests for this file handle.
    ///
    /// If this returns `ReplyError::Cancelled`, no `Release` event will arrive for this file
    /// handle. The caller must clean up any resources associated with `fh` immediately.
    pub fn reply(mut self, fh: u64) -> Result<(), ReplyError> {
        let open_out = FuseOpenOut {
            fh,
            open_flags: self.file_info.open_flags_out().bits(),
            backing_id: 0,
        };
        reply_ok_cancellable(&mut self.request, as_bytes(&open_out))
    }
}

/// Release a reference to a file.
#[derive(Debug)]
pub struct Release {
    pub(crate) request: RequestGuard,
    pub inode: u64,
    pub fh: u64,
    pub flags: libc::c_int,
}

impl Release {
    pub fn reply(mut self) -> io::Result<()> {
        reply_ok(&mut self.request, &[])
    }
}

/// Read from a file.
#[derive(Debug)]
pub struct Read {
    pub(crate) request: RequestGuard,
    pub inode: u64,
    pub fh: u64,
    pub size: usize,
    pub offset: u64,
}

impl Read {
    pub fn reply(mut self, data: &[u8]) -> io::Result<()> {
        if data.len() > self.size {
            return Err(io::Error::other(format!(
                "Read reply ({} bytes) exceeds requested size ({} bytes)",
                data.len(),
                self.size,
            )));
        }
        reply_ok(&mut self.request, data)
    }

    pub fn reply_vectored(self, data: &[IoSlice<'_>]) -> io::Result<()> {
        let total: usize = data.iter().map(|s| s.len()).sum();
        if total > self.size {
            return Err(io::Error::other(format!(
                "Read reply_vectored ({total} bytes) exceeds requested size ({} bytes)",
                self.size,
            )));
        }
        let fd = self.request.fd.as_raw_fd();
        let unique = self.request.unique;
        self.request.disarm();
        send_reply_vectored(fd, unique, data, total)
    }
}

pub enum SetTime {
    /// The time should be set to the current time.
    Now,

    /// Time since the epoch.
    Time(Duration),
}

/// Convert FUSE wire time fields to a `Duration`, clamping nanoseconds to valid range
/// and clamping pre-epoch seconds to zero (the FUSE protocol uses u64 for seconds
/// and cannot represent negative times).
fn duration_from_c(secs: libc::time_t, nsecs: i64) -> Duration {
    let nsec = nsecs.clamp(0, 999_999_999) as u32;
    Duration::new(secs.max(0) as u64, nsec)
}

/// Set attributes of a file.
#[derive(Debug)]
pub struct Setattr {
    pub(crate) request: RequestGuard,
    pub inode: u64,
    pub fh: Option<u64>,
    pub to_set: sys::FattrFlags,
    pub(crate) stat: Stat,
}

impl Setattr {
    /// `Some` if the mode field should be modified.
    pub fn mode(&self) -> Option<libc::mode_t> {
        self.to_set
            .contains(sys::FattrFlags::MODE)
            .then_some(self.stat.st_mode)
    }

    /// `Some` if the uid field should be modified.
    pub fn uid(&self) -> Option<libc::uid_t> {
        self.to_set
            .contains(sys::FattrFlags::UID)
            .then_some(self.stat.st_uid)
    }

    /// `Some` if the gid field should be modified.
    pub fn gid(&self) -> Option<libc::gid_t> {
        self.to_set
            .contains(sys::FattrFlags::GID)
            .then_some(self.stat.st_gid)
    }

    /// `Some` if the size field should be modified.
    pub fn size(&self) -> Option<u64> {
        self.to_set
            .contains(sys::FattrFlags::SIZE)
            .then_some(self.stat.st_size as u64)
    }

    /// `Some` if the atime field should be modified.
    pub fn atime(&self) -> Option<SetTime> {
        if self.to_set.contains(sys::FattrFlags::ATIME) {
            Some(SetTime::Time(duration_from_c(
                self.stat.st_atime,
                self.stat.st_atime_nsec,
            )))
        } else if self.to_set.contains(sys::FattrFlags::ATIME_NOW) {
            Some(SetTime::Now)
        } else {
            None
        }
    }

    /// `Some` if the mtime field should be modified.
    pub fn mtime(&self) -> Option<SetTime> {
        if self.to_set.contains(sys::FattrFlags::MTIME) {
            Some(SetTime::Time(duration_from_c(
                self.stat.st_mtime,
                self.stat.st_mtime_nsec,
            )))
        } else if self.to_set.contains(sys::FattrFlags::MTIME_NOW) {
            Some(SetTime::Now)
        } else {
            None
        }
    }

    /// `Some` if the ctime field should be modified.
    pub fn ctime(&self) -> Option<Duration> {
        self.to_set
            .contains(sys::FattrFlags::CTIME)
            .then(|| duration_from_c(self.stat.st_ctime, self.stat.st_ctime_nsec))
    }

    /// Send a reply for a `Setattr` request.
    pub fn reply(mut self, stat: &libc::stat, timeout: f64) -> io::Result<()> {
        reply_attr(&mut self.request, stat, timeout)
    }
}

/// Remove a hard-link to a file. Note that the removed file may still have active references which
/// should still be usable. This only unlinks the file from one directory.
#[derive(Debug)]
pub struct Unlink {
    pub(crate) request: RequestGuard,
    pub parent: u64,
    pub file_name: OsString,
}

impl Unlink {
    /// Send a reply for an `Unlink` request.
    pub fn reply(mut self) -> io::Result<()> {
        reply_ok(&mut self.request, &[])
    }
}

/// Remove a directory entry. Note that the removed directory may still have active references
/// which should still be usable. Only its hard link into the directory hierarchy is dropped.
#[derive(Debug)]
pub struct Rmdir {
    pub(crate) request: RequestGuard,
    pub parent: u64,
    pub dir_name: OsString,
}

impl Rmdir {
    /// Send a reply for an `Rmdir` request.
    pub fn reply(mut self) -> io::Result<()> {
        reply_ok(&mut self.request, &[])
    }
}

/// Rename a file or directory.
#[derive(Debug)]
pub struct Rename {
    pub(crate) request: RequestGuard,
    pub parent: u64,
    pub name: OsString,
    pub new_parent: u64,
    pub new_name: OsString,
    pub flags: libc::c_int,
}

impl Rename {
    pub fn reply(mut self) -> io::Result<()> {
        reply_ok(&mut self.request, &[])
    }
}

/// Write to a file.
#[derive(Debug)]
pub struct Write {
    pub(crate) request: RequestGuard,
    pub inode: u64,
    pub fh: u64,
    data_offset: usize,
    pub size: usize,
    pub offset: u64,

    /// We keep a reference count on the buffer so it will not be cleared until it is used up by
    /// requests borrowing data from it, like `Write`.
    pub(crate) buffer: Arc<Vec<u8>>,
}

impl Write {
    pub(crate) fn new(
        request: RequestGuard,
        inode: u64,
        fh: u64,
        data_offset: usize,
        size: usize,
        offset: u64,
        buffer: Arc<Vec<u8>>,
    ) -> Self {
        Self {
            request,
            inode,
            fh,
            data_offset,
            size,
            offset,
            buffer,
        }
    }

    pub fn reply(mut self, size: usize) -> io::Result<()> {
        if size > self.size {
            return Err(io::Error::other(format!(
                "write reply size ({size}) exceeds original write size ({})",
                self.size,
            )));
        }
        let size =
            u32::try_from(size).map_err(|_| io::Error::other("write size exceeds u32::MAX"))?;
        let write_out = FuseWriteOut { size, padding: 0 };
        reply_ok(&mut self.request, as_bytes(&write_out))
    }

    #[inline]
    pub fn data(&self) -> &[u8] {
        &self.buffer[self.data_offset..self.data_offset + self.size]
    }
}

/// Read a symbolic link.
#[derive(Debug)]
pub struct Readlink {
    pub(crate) request: RequestGuard,
    pub inode: u64,
}

impl Readlink {
    pub fn reply(self, data: &OsStr) -> io::Result<()> {
        let data = CString::new(data.as_bytes())
            .map_err(|_| io::Error::other("tried to reply with invalid link"))?;

        self.c_reply(&data)
    }

    pub fn c_reply(mut self, data: &CStr) -> io::Result<()> {
        // The FUSE kernel protocol expects the link target without a NUL terminator;
        // the kernel adds its own NUL internally via kmemdup_nul().
        reply_ok(&mut self.request, data.to_bytes())
    }
}

/// Get the size of the extended attribute list.
#[derive(Debug)]
pub struct ListXAttrSize {
    pub(crate) request: RequestGuard,
    pub inode: u64,
}

impl ListXAttrSize {
    pub fn reply(mut self, size: usize) -> io::Result<()> {
        reply_xattr_size(&mut self.request, size)
    }
}

/// List extended attributes.
#[derive(Debug)]
pub struct ListXAttr {
    pub(crate) request: RequestGuard,
    pub inode: u64,
    pub size: usize,
    response: Vec<u8>,
}

impl ListXAttr {
    pub(crate) fn new(request: RequestGuard, inode: u64, size: usize) -> Self {
        Self {
            request,
            inode,
            size,
            response: Vec::with_capacity(size),
        }
    }

    /// Check whether we can add `len` bytes to the buffer. This must already include the
    /// terminating zero.
    fn check_add(&self, len: usize) -> bool {
        self.response.len() + len <= self.size
    }

    /// Add an extended attribute entry to the response list.
    ///
    /// This returns `Full` if the entry would overflow the caller's buffer, but will not fail the
    /// request. Use `fail_full()` to send the default reply for a too-small buffer, or `reply()`
    /// to reply with success.
    pub fn add(&mut self, name: &OsStr) -> ReplyBufState {
        unsafe { self.add_bytes_without_zero(name.as_bytes()) }
    }

    /// Add a raw attribute name the response list. It must not contain any zeroes. The terminating
    /// zero byte will be appended to the buffer.
    ///
    /// See `add` for details.
    ///
    /// # Safety
    ///
    /// Technically safe to call, but zero bytes in `name` will be treated as separators and
    /// cause confusion.
    pub unsafe fn add_bytes_without_zero(&mut self, name: &[u8]) -> ReplyBufState {
        if !self.check_add(name.len() + 1) {
            return ReplyBufState::Full;
        }

        self.response.extend(name);
        self.response.push(0);

        ReplyBufState::Ok
    }

    /// Add a raw attribute name which is already zero terminated to the response list.
    ///
    /// See `add` for details.
    ///
    /// # Safety
    ///
    /// Technically safe to call, and could technically be used to add multiple entries at once,
    /// but is not meant to be used that way. Zero bytes in the middle will be treated as entry
    /// separators.
    pub unsafe fn add_bytes_with_zero(&mut self, name: &[u8]) -> ReplyBufState {
        if !self.check_add(name.len()) {
            return ReplyBufState::Full;
        }

        self.response.extend(name);

        ReplyBufState::Ok
    }

    /// Add a raw attribute name which is already zero terminated to the response list.
    ///
    /// This is the safe version as it uses a `CStr`.
    ///
    /// See `add` for details.
    pub fn add_c_string(&mut self, name: &CStr) -> ReplyBufState {
        unsafe { self.add_bytes_with_zero(name.to_bytes_with_nul()) }
    }

    /// Try to replace the current reply buffer with a raw data buffer. If the provided data is too
    /// large it will be returned as an error.
    pub fn set_raw_reply(&mut self, data: Vec<u8>) -> Result<(), Vec<u8>> {
        if data.len() > self.size {
            return Err(data);
        }

        self.response = data;
        Ok(())
    }

    /// Reply with the standard error for a too-small size.
    pub fn fail_full(self) -> io::Result<()> {
        self.fail(libc::ERANGE)
    }

    /// Reply to the request with the current data buffer.
    pub fn reply(mut self) -> io::Result<()> {
        reply_ok(&mut self.request, &self.response)
    }

    /// Reply to the request with either an error (`ERANGE` if the data doesn't fit) or with the
    /// provided raw buffer discarding anything previously added to the reply.
    pub fn reply_raw(mut self, data: &[u8]) -> io::Result<()> {
        if data.len() > self.size {
            return self.fail_full();
        }

        reply_ok(&mut self.request, data)
    }
}

/// Get the size of an extended attribute.
#[derive(Debug)]
pub struct GetXAttrSize {
    pub(crate) request: RequestGuard,
    pub inode: u64,
    pub attr_name: OsString,
}

impl GetXAttrSize {
    pub fn reply(mut self, size: usize) -> io::Result<()> {
        reply_xattr_size(&mut self.request, size)
    }
}

/// Get an extended attribute.
#[derive(Debug)]
pub struct GetXAttr {
    pub(crate) request: RequestGuard,
    pub inode: u64,
    pub attr_name: OsString,
    pub size: usize,
}

impl GetXAttr {
    /// Reply to the request either with an error (`ERANGE` if the buffer doesn't fit), or with the
    /// provided data.
    pub fn reply(mut self, data: &[u8]) -> io::Result<()> {
        if data.len() > self.size {
            return self.fail(libc::ERANGE);
        }

        reply_ok(&mut self.request, data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::FromRawFd;

    /// Create a pipe and return (read_fd, write_fd) as raw fds.
    fn pipe() -> (i32, i32) {
        let mut fds = [0i32; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        (fds[0], fds[1])
    }

    /// Read exactly `n` bytes from a raw fd.
    fn read_exact(fd: i32, n: usize) -> Vec<u8> {
        let mut buf = vec![0u8; n];
        let mut total = 0;
        while total < n {
            let rc = unsafe {
                libc::read(
                    fd,
                    buf[total..].as_mut_ptr() as *mut libc::c_void,
                    n - total,
                )
            };
            assert!(rc > 0, "short read from pipe");
            total += rc as usize;
        }
        buf
    }

    #[test]
    fn send_reply_header_format() {
        let (r, w) = pipe();
        let _r_guard = unsafe { std::os::fd::OwnedFd::from_raw_fd(r) };
        let _w_guard = unsafe { std::os::fd::OwnedFd::from_raw_fd(w) };

        let body = b"hello";
        send_reply(w, 42, 0, body).unwrap();

        let header_size = mem::size_of::<FuseOutHeader>();
        let buf = read_exact(r, header_size + body.len());

        // Parse the header.
        let header: FuseOutHeader =
            unsafe { (buf.as_ptr() as *const FuseOutHeader).read_unaligned() };
        assert_eq!(header.len as usize, header_size + body.len());
        assert_eq!(header.error, 0);
        assert_eq!(header.unique, 42);

        // Verify the body.
        assert_eq!(&buf[header_size..], body);
    }

    #[test]
    fn send_reply_error() {
        let (r, w) = pipe();
        let _r_guard = unsafe { std::os::fd::OwnedFd::from_raw_fd(r) };
        let _w_guard = unsafe { std::os::fd::OwnedFd::from_raw_fd(w) };

        send_error_reply(w, 99, libc::ENOENT).unwrap();

        let header_size = mem::size_of::<FuseOutHeader>();
        let buf = read_exact(r, header_size);

        let header: FuseOutHeader =
            unsafe { (buf.as_ptr() as *const FuseOutHeader).read_unaligned() };
        assert_eq!(header.len as usize, header_size);
        assert_eq!(header.error, -libc::ENOENT);
        assert_eq!(header.unique, 99);
    }

    #[test]
    fn send_reply_vectored_combines_slices() {
        let (r, w) = pipe();
        let _r_guard = unsafe { std::os::fd::OwnedFd::from_raw_fd(r) };
        let _w_guard = unsafe { std::os::fd::OwnedFd::from_raw_fd(w) };

        let a = b"abc";
        let b = b"defgh";
        let slices = [IoSlice::new(a), IoSlice::new(b)];
        send_reply_vectored(w, 7, &slices, a.len() + b.len()).unwrap();

        let header_size = mem::size_of::<FuseOutHeader>();
        let total = header_size + a.len() + b.len();
        let buf = read_exact(r, total);

        let header: FuseOutHeader =
            unsafe { (buf.as_ptr() as *const FuseOutHeader).read_unaligned() };
        assert_eq!(header.len as usize, total);
        assert_eq!(header.error, 0);
        assert_eq!(header.unique, 7);
        assert_eq!(&buf[header_size..header_size + 3], b"abc");
        assert_eq!(&buf[header_size + 3..], b"defgh");
    }

    #[test]
    fn as_bytes_roundtrip() {
        let header = FuseOutHeader {
            len: 16,
            error: -2,
            unique: 0xDEAD_BEEF,
        };
        let bytes = as_bytes(&header);
        assert_eq!(bytes.len(), mem::size_of::<FuseOutHeader>());

        let recovered: FuseOutHeader =
            unsafe { (bytes.as_ptr() as *const FuseOutHeader).read_unaligned() };
        assert_eq!(recovered.len, 16);
        assert_eq!(recovered.error, -2);
        assert_eq!(recovered.unique, 0xDEAD_BEEF);
    }
}
