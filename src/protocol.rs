//! FUSE kernel protocol types.
//!
//! These are Rust translations of the structures defined in `<linux/fuse.h>`.
//! Only the opcodes and structures needed by this crate are included.

use std::ffi::{CStr, OsStr};
use std::io;
use std::mem;
use std::os::unix::ffi::OsStrExt;

/// FUSE kernel protocol major version.
pub const FUSE_KERNEL_VERSION: u32 = 7;

/// FUSE kernel protocol minor version we target (7.31).
pub const FUSE_KERNEL_MINOR_VERSION: u32 = 31;

/// Node ID of the root inode.
pub const FUSE_ROOT_ID: u64 = 1;

/// Minimum read buffer size required by the kernel.
pub const FUSE_MIN_READ_BUFFER: usize = 8192;

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Opcode {
    Lookup = 1,
    Forget = 2,
    Getattr = 3,
    Setattr = 4,
    Readlink = 5,
    Mknod = 8,
    Mkdir = 9,
    Unlink = 10,
    Rmdir = 11,
    Open = 14,
    Read = 15,
    Write = 16,
    Statfs = 17,
    Release = 18,
    Getxattr = 22,
    Listxattr = 23,
    Init = 26,
    Readdir = 28,
    Create = 35,
    Interrupt = 36,
    Destroy = 38,
    BatchForget = 42,
    Readdirplus = 44,
    Rename2 = 45,
}

impl Opcode {
    pub fn from_u32(v: u32) -> Option<Self> {
        Some(match v {
            1 => Self::Lookup,
            2 => Self::Forget,
            3 => Self::Getattr,
            4 => Self::Setattr,
            5 => Self::Readlink,
            8 => Self::Mknod,
            9 => Self::Mkdir,
            10 => Self::Unlink,
            11 => Self::Rmdir,
            14 => Self::Open,
            15 => Self::Read,
            16 => Self::Write,
            17 => Self::Statfs,
            18 => Self::Release,
            22 => Self::Getxattr,
            23 => Self::Listxattr,
            26 => Self::Init,
            28 => Self::Readdir,
            35 => Self::Create,
            36 => Self::Interrupt,
            38 => Self::Destroy,
            42 => Self::BatchForget,
            44 => Self::Readdirplus,
            45 => Self::Rename2,
            _ => return None,
        })
    }
}

bitflags::bitflags! {
    /// FATTR_* flags indicating which fields are valid in a setattr request.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct FattrFlags: u32 {
        const MODE = 1 << 0;
        const UID = 1 << 1;
        const GID = 1 << 2;
        const SIZE = 1 << 3;
        const ATIME = 1 << 4;
        const MTIME = 1 << 5;
        const FH = 1 << 6;
        const ATIME_NOW = 1 << 7;
        const MTIME_NOW = 1 << 8;
        const CTIME = 1 << 10;
    }

    /// FOPEN_* flags for open/create replies.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct FopenFlags: u32 {
        const DIRECT_IO = 1 << 0;
        const KEEP_CACHE = 1 << 1;
        const NONSEEKABLE = 1 << 2;
        const CACHE_DIR = 1 << 3;
        const STREAM = 1 << 4;
        const NOFLUSH = 1 << 5;
    }

    /// FUSE_INIT capability flags.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct InitFlags: u32 {
        const ASYNC_READ = 1 << 0;
        const ATOMIC_O_TRUNC = 1 << 3;
        const BIG_WRITES = 1 << 5;
        const DO_READDIRPLUS = 1 << 13;
        const READDIRPLUS_AUTO = 1 << 14;
        const NO_OPEN_SUPPORT = 1 << 17;
        const MAX_PAGES = 1 << 22;
        const NO_OPENDIR_SUPPORT = 1 << 24;
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FuseInHeader {
    pub len: u32,
    pub opcode: u32,
    pub unique: u64,
    pub nodeid: u64,
    pub uid: u32,
    pub gid: u32,
    pub pid: u32,
    pub total_extlen: u16,
    pub padding: u16,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FuseOutHeader {
    pub len: u32,
    pub error: i32,
    pub unique: u64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FuseAttr {
    pub ino: u64,
    pub size: u64,
    pub blocks: u64,
    pub atime: u64,
    pub mtime: u64,
    pub ctime: u64,
    pub atimensec: u32,
    pub mtimensec: u32,
    pub ctimensec: u32,
    pub mode: u32,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub rdev: u32,
    pub blksize: u32,
    pub flags: u32,
}

impl FuseAttr {
    pub fn from_stat(s: &libc::stat) -> Self {
        // The FUSE wire format uses u64 for seconds, so pre-epoch timestamps
        // cannot be represented. Clamp to 0 rather than silently wrapping.
        Self {
            ino: s.st_ino,
            size: s.st_size as u64,
            blocks: s.st_blocks as u64,
            atime: s.st_atime.max(0) as u64,
            mtime: s.st_mtime.max(0) as u64,
            ctime: s.st_ctime.max(0) as u64,
            atimensec: s.st_atime_nsec.max(0) as u32,
            mtimensec: s.st_mtime_nsec.max(0) as u32,
            ctimensec: s.st_ctime_nsec.max(0) as u32,
            mode: s.st_mode,
            nlink: s.st_nlink as u32,
            uid: s.st_uid,
            gid: s.st_gid,
            rdev: s.st_rdev as u32,
            blksize: s.st_blksize as u32,
            flags: 0,
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FuseEntryOut {
    pub nodeid: u64,
    pub generation: u64,
    pub entry_valid: u64,
    pub attr_valid: u64,
    pub entry_valid_nsec: u32,
    pub attr_valid_nsec: u32,
    pub attr: FuseAttr,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FuseAttrOut {
    pub attr_valid: u64,
    pub attr_valid_nsec: u32,
    pub dummy: u32,
    pub attr: FuseAttr,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FuseKstatfs {
    pub blocks: u64,
    pub bfree: u64,
    pub bavail: u64,
    pub files: u64,
    pub ffree: u64,
    pub bsize: u32,
    pub namelen: u32,
    pub frsize: u32,
    pub padding: u32,
    pub spare: [u32; 6],
}

impl FuseKstatfs {
    pub fn from_statvfs(s: &libc::statvfs) -> Self {
        Self {
            blocks: s.f_blocks,
            bfree: s.f_bfree,
            bavail: s.f_bavail,
            files: s.f_files,
            ffree: s.f_ffree,
            bsize: s.f_bsize as u32,
            namelen: s.f_namemax as u32,
            frsize: s.f_frsize as u32,
            padding: 0,
            spare: [0; 6],
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FuseForgetIn {
    pub nlookup: u64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FuseBatchForgetIn {
    pub count: u32,
    pub dummy: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FuseForgetOne {
    pub nodeid: u64,
    pub nlookup: u64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FuseSetattrIn {
    pub valid: u32,
    pub padding: u32,
    pub fh: u64,
    pub size: u64,
    pub lock_owner: u64,
    pub atime: u64,
    pub mtime: u64,
    pub ctime: u64,
    pub atimensec: u32,
    pub mtimensec: u32,
    pub ctimensec: u32,
    pub mode: u32,
    pub unused4: u32,
    pub uid: u32,
    pub gid: u32,
    pub unused5: u32,
}

impl FuseSetattrIn {
    /// Convert the setattr fields to a `libc::stat` for use by the `Setattr` request.
    /// Only the fields that can appear in a setattr request are populated.
    pub fn to_stat(self) -> libc::stat {
        let mut stat: libc::stat = unsafe { mem::zeroed() };
        stat.st_mode = self.mode;
        stat.st_uid = self.uid;
        stat.st_gid = self.gid;
        stat.st_size = self.size as i64;
        stat.st_atime = self.atime as i64;
        stat.st_atime_nsec = self.atimensec as i64;
        stat.st_mtime = self.mtime as i64;
        stat.st_mtime_nsec = self.mtimensec as i64;
        stat.st_ctime = self.ctime as i64;
        stat.st_ctime_nsec = self.ctimensec as i64;
        stat
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FuseOpenIn {
    pub flags: u32,
    pub open_flags: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FuseOpenOut {
    pub fh: u64,
    pub open_flags: u32,
    pub backing_id: i32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FuseCreateIn {
    pub flags: u32,
    pub mode: u32,
    pub umask: u32,
    pub open_flags: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FuseReleaseIn {
    pub fh: u64,
    pub flags: u32,
    pub release_flags: u32,
    pub lock_owner: u64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FuseReadIn {
    pub fh: u64,
    pub offset: u64,
    pub size: u32,
    pub read_flags: u32,
    pub lock_owner: u64,
    pub flags: u32,
    pub padding: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FuseWriteIn {
    pub fh: u64,
    pub offset: u64,
    pub size: u32,
    pub write_flags: u32,
    pub lock_owner: u64,
    pub flags: u32,
    pub padding: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FuseWriteOut {
    pub size: u32,
    pub padding: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FuseMknodIn {
    pub mode: u32,
    pub rdev: u32,
    pub umask: u32,
    pub padding: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FuseMkdirIn {
    pub mode: u32,
    pub umask: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FuseRename2In {
    pub newdir: u64,
    pub flags: u32,
    pub padding: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FuseInitIn {
    pub major: u32,
    pub minor: u32,
    pub max_readahead: u32,
    pub flags: u32,
    pub flags2: u32,
    pub unused: [u32; 11],
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FuseInitOut {
    pub major: u32,
    pub minor: u32,
    pub max_readahead: u32,
    pub flags: u32,
    pub max_background: u16,
    pub congestion_threshold: u16,
    pub max_write: u32,
    pub time_gran: u32,
    pub max_pages: u16,
    pub map_alignment: u16,
    pub flags2: u32,
    pub max_stack_depth: u32,
    pub request_timeout: u16,
    pub unused: [u16; 11],
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FuseGetxattrIn {
    pub size: u32,
    pub padding: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FuseGetxattrOut {
    pub size: u32,
    pub padding: u32,
}

/// Fixed-size prefix of `fuse_dirent`. The variable-length name follows immediately.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FuseDirent {
    pub ino: u64,
    pub off: u64,
    pub namelen: u32,
    pub typ: u32,
    // name follows, padded to 8-byte alignment
}

/// The size of the fixed `fuse_dirent` header (without name).
pub const FUSE_DIRENT_HEADER_SIZE: usize = mem::size_of::<FuseDirent>();

/// Align `x` up to the 8-byte boundary required by the FUSE dirent wire format.
#[inline]
pub const fn fuse_dirent_align(x: usize) -> usize {
    (x + 7) & !7
}

/// Total size of a dirent entry including name and padding.
pub const fn fuse_dirent_size(namelen: usize) -> usize {
    fuse_dirent_align(FUSE_DIRENT_HEADER_SIZE + namelen)
}

pub const FUSE_ENTRY_OUT_SIZE: usize = mem::size_of::<FuseEntryOut>();

/// Total size of a direntplus entry (entry_out + dirent header + name + padding).
pub const fn fuse_direntplus_size(namelen: usize) -> usize {
    fuse_dirent_align(FUSE_ENTRY_OUT_SIZE + FUSE_DIRENT_HEADER_SIZE + namelen)
}

/// Split a timeout into `(whole_seconds, nanoseconds)` for the FUSE wire format,
/// which stores the two parts in separate `u64`/`u32` fields.
pub fn split_timeout(timeout: f64) -> (u64, u32) {
    // Fast-path for the common static-cache sentinel; also avoids float overflow
    // (f64::MAX as u64 saturates, making the nsec subtraction produce u32::MAX).
    if timeout >= u64::MAX as f64 {
        return (u64::MAX, 999_999_999);
    }
    let secs = timeout as u64;
    let nsec = ((timeout - secs as f64) * 1e9) as u32;
    (secs, nsec)
}

/// Extract a NUL-terminated name from a raw byte slice.
///
/// Stops at the first NUL byte; uses the whole slice if no NUL is present.
pub fn name_from_bytes(data: &[u8]) -> &OsStr {
    let bytes = CStr::from_bytes_until_nul(data)
        .map(CStr::to_bytes)
        .unwrap_or(data);
    OsStr::from_bytes(bytes)
}

/// Extract the name from a FUSE request where the name follows a fixed-size header `T`.
pub fn name_after<T>(data: &[u8]) -> io::Result<&OsStr> {
    if data.len() < mem::size_of::<T>() {
        return Err(io::Error::other(
            "truncated FUSE message: body too short for name",
        ));
    }
    Ok(name_from_bytes(&data[mem::size_of::<T>()..]))
}

/// Extract two NUL-separated names from a FUSE request (used by rename2).
pub fn two_names_after<T>(data: &[u8]) -> io::Result<(&OsStr, &OsStr)> {
    if data.len() < mem::size_of::<T>() {
        return Err(io::Error::other(
            "truncated FUSE message: body too short for names",
        ));
    }
    let rest = &data[mem::size_of::<T>()..];
    let nul_pos = rest.iter().position(|&b| b == 0).ok_or_else(|| {
        io::Error::other("malformed FUSE rename: missing NUL separator between names")
    })?;
    let first = OsStr::from_bytes(&rest[..nul_pos]);
    let second = name_from_bytes(&rest[nul_pos + 1..]);
    Ok((first, second))
}

pub fn entry_out_from_param(entry: &super::sys::EntryParam) -> FuseEntryOut {
    let (attr_valid, attr_valid_nsec) = split_timeout(entry.attr_timeout);
    let (entry_valid, entry_valid_nsec) = split_timeout(entry.entry_timeout);

    FuseEntryOut {
        nodeid: entry.inode,
        generation: entry.generation,
        entry_valid,
        attr_valid,
        entry_valid_nsec,
        attr_valid_nsec,
        attr: FuseAttr::from_stat(&entry.attr),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Validate that our `repr(C)` structs match the sizes defined in `<linux/fuse.h>`.
    /// A mismatch here means the kernel will misinterpret our requests or replies.
    #[test]
    fn wire_struct_sizes() {
        assert_eq!(mem::size_of::<FuseInHeader>(), 40);
        assert_eq!(mem::size_of::<FuseOutHeader>(), 16);
        assert_eq!(mem::size_of::<FuseAttr>(), 88);
        assert_eq!(mem::size_of::<FuseEntryOut>(), 128);
        assert_eq!(mem::size_of::<FuseAttrOut>(), 104);
        assert_eq!(mem::size_of::<FuseKstatfs>(), 80);
        assert_eq!(mem::size_of::<FuseInitIn>(), 64);
        assert_eq!(mem::size_of::<FuseInitOut>(), 64);
        assert_eq!(mem::size_of::<FuseOpenIn>(), 8);
        assert_eq!(mem::size_of::<FuseOpenOut>(), 16);
        assert_eq!(mem::size_of::<FuseForgetIn>(), 8);
        assert_eq!(mem::size_of::<FuseBatchForgetIn>(), 8);
        assert_eq!(mem::size_of::<FuseForgetOne>(), 16);
        assert_eq!(mem::size_of::<FuseSetattrIn>(), 88);
        assert_eq!(mem::size_of::<FuseCreateIn>(), 16);
        assert_eq!(mem::size_of::<FuseReleaseIn>(), 24);
        assert_eq!(mem::size_of::<FuseReadIn>(), 40);
        assert_eq!(mem::size_of::<FuseWriteIn>(), 40);
        assert_eq!(mem::size_of::<FuseWriteOut>(), 8);
        assert_eq!(mem::size_of::<FuseMknodIn>(), 16);
        assert_eq!(mem::size_of::<FuseMkdirIn>(), 8);
        assert_eq!(mem::size_of::<FuseRename2In>(), 16);
        assert_eq!(mem::size_of::<FuseGetxattrIn>(), 8);
        assert_eq!(mem::size_of::<FuseGetxattrOut>(), 8);
        assert_eq!(mem::size_of::<FuseDirent>(), FUSE_DIRENT_HEADER_SIZE);
        assert_eq!(FUSE_DIRENT_HEADER_SIZE, 24);
        assert_eq!(FUSE_ENTRY_OUT_SIZE, 128);
    }

    #[test]
    fn dirent_alignment() {
        assert_eq!(fuse_dirent_align(0), 0);
        assert_eq!(fuse_dirent_align(1), 8);
        assert_eq!(fuse_dirent_align(7), 8);
        assert_eq!(fuse_dirent_align(8), 8);
        assert_eq!(fuse_dirent_align(9), 16);
    }

    #[test]
    fn dirent_sizes() {
        // Empty name: header only, aligned.
        assert_eq!(fuse_dirent_size(0), 24);
        // 1-byte name: 24 + 1 = 25, aligned to 32.
        assert_eq!(fuse_dirent_size(1), 32);
        // 8-byte name: 24 + 8 = 32, already aligned.
        assert_eq!(fuse_dirent_size(8), 32);
        // 9-byte name: 24 + 9 = 33, aligned to 40.
        assert_eq!(fuse_dirent_size(9), 40);
    }

    #[test]
    fn direntplus_sizes() {
        // entry_out(128) + dirent_header(24) + name, aligned.
        assert_eq!(fuse_direntplus_size(0), 152);
        assert_eq!(fuse_direntplus_size(1), 160);
        assert_eq!(fuse_direntplus_size(8), 160);
        assert_eq!(fuse_direntplus_size(9), 168);
    }

    #[test]
    fn split_timeout_values() {
        assert_eq!(split_timeout(0.0), (0, 0));
        assert_eq!(split_timeout(1.0), (1, 0));
        assert_eq!(split_timeout(1.5), (1, 500_000_000));
        assert_eq!(split_timeout(0.001), (0, 1_000_000));
        assert_eq!(split_timeout(f64::MAX), (u64::MAX, 999_999_999));
    }

    #[test]
    fn opcode_from_u32_roundtrip() {
        // Every variant must round-trip through from_u32 using its discriminant.
        // This catches divergence between the repr(u32) values and the match arms.
        let variants = [
            Opcode::Lookup,
            Opcode::Forget,
            Opcode::Getattr,
            Opcode::Setattr,
            Opcode::Readlink,
            Opcode::Mknod,
            Opcode::Mkdir,
            Opcode::Unlink,
            Opcode::Rmdir,
            Opcode::Open,
            Opcode::Read,
            Opcode::Write,
            Opcode::Statfs,
            Opcode::Release,
            Opcode::Getxattr,
            Opcode::Listxattr,
            Opcode::Init,
            Opcode::BatchForget,
            Opcode::Readdir,
            Opcode::Create,
            Opcode::Interrupt,
            Opcode::Destroy,
            Opcode::Readdirplus,
            Opcode::Rename2,
        ];
        for opcode in variants {
            assert_eq!(
                Opcode::from_u32(opcode as u32),
                Some(opcode),
                "round-trip failed for {opcode:?}"
            );
        }
        // Unknown opcodes must return None.
        assert_eq!(Opcode::from_u32(0), None);
        assert_eq!(Opcode::from_u32(99), None);
    }
}
