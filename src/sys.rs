//! Public types for the FUSE API.
//!
//! This module contains types that are part of the public API. In the previous libfuse3-based
//! implementation, this module contained FFI bindings. Now all types are pure Rust.

use std::ffi::CStr;

use crate::protocol::{self, FUSE_DIRENT_HEADER_SIZE, FUSE_ENTRY_OUT_SIZE, FuseDirent};
use crate::requests::as_bytes;

/// Re-export FATTR_* flags for setattr requests.
pub use crate::protocol::FattrFlags;

/// Node ID of the root i-node.
pub const ROOT_ID: u64 = protocol::FUSE_ROOT_ID;

/// Convert `st_mode` to the `DT_*` dirent type used in the FUSE wire format.
#[inline]
fn mode_to_dirent_type(mode: u32) -> u32 {
    (mode >> 12) & 0xf
}

/// FUSE entry parameter for lookup/create/mkdir/mknod replies.
pub struct EntryParam {
    pub inode: u64,
    pub generation: u64,
    pub attr: libc::stat,
    pub attr_timeout: f64,
    pub entry_timeout: f64,
}

impl EntryParam {
    /// A simple entry has a maximum attribute/entry timeout value and always a generatio of 1.
    /// This is a convenience method used since we mostly use this for static unchangable archives.
    pub fn simple(inode: u64, attr: libc::stat) -> Self {
        Self {
            inode,
            generation: 1,
            attr,
            attr_timeout: f64::MAX,
            entry_timeout: f64::MAX,
        }
    }
}

/// State of ReplyBuf after last add_entry call
#[must_use]
pub enum ReplyBufState {
    /// Entry was successfully added to ReplyBuf
    Ok,
    /// Entry did not fit into ReplyBuf, was not added
    Full,
}

impl ReplyBufState {
    #[inline]
    pub fn is_full(&self) -> bool {
        matches!(self, &ReplyBufState::Full)
    }
}

/// This is used to communicate options for `Open` and `Create` requests.
///
/// In the previous implementation this was backed by a C struct with bitfields accessed via glue
/// code. Now it is a pure Rust struct.
#[derive(Clone, Debug, Default)]
pub struct FuseFileInfo {
    // Boolean flags mapped to FOPEN_* in the reply.
    direct_io: bool,
    keep_cache: bool,
    nonseekable: bool,
    cache_readdir: bool,
    noflush: bool,
}

impl FuseFileInfo {
    /// Convert the boolean flags to FOPEN_* bitmask for the reply.
    pub(crate) fn open_flags_out(&self) -> protocol::FopenFlags {
        use protocol::FopenFlags;
        let mut out = FopenFlags::empty();
        out.set(FopenFlags::DIRECT_IO, self.direct_io);
        out.set(FopenFlags::KEEP_CACHE, self.keep_cache);
        out.set(FopenFlags::NONSEEKABLE, self.nonseekable);
        out.set(FopenFlags::CACHE_DIR, self.cache_readdir);
        out.set(FopenFlags::NOFLUSH, self.noflush);
        out
    }

    pub fn set_direct_io(&mut self, value: bool) {
        self.direct_io = value;
    }
    pub fn get_direct_io(&self) -> bool {
        self.direct_io
    }

    pub fn set_keep_cache(&mut self, value: bool) {
        self.keep_cache = value;
    }
    pub fn get_keep_cache(&self) -> bool {
        self.keep_cache
    }

    pub fn set_nonseekable(&mut self, value: bool) {
        self.nonseekable = value;
    }
    pub fn get_nonseekable(&self) -> bool {
        self.nonseekable
    }

    pub fn set_cache_readdir(&mut self, value: bool) {
        self.cache_readdir = value;
    }
    pub fn get_cache_readdir(&self) -> bool {
        self.cache_readdir
    }

    pub fn set_noflush(&mut self, value: bool) {
        self.noflush = value;
    }
    pub fn get_noflush(&self) -> bool {
        self.noflush
    }
}

/// Used to correctly fill and reply the buffer for the readdir/readdirplus callbacks.
///
/// In the previous implementation, this called libfuse's `fuse_add_direntry`/
/// `fuse_add_direntry_plus`. Now we pack the entries ourselves according to the kernel protocol.
pub struct ReplyBuf {
    /// Internal buffer holding the binary data.
    buffer: Vec<u8>,
    /// Offset up to which the buffer is filled.
    filled: usize,
}

impl std::fmt::Debug for ReplyBuf {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("ReplyBuf")
            .field("filled", &self.filled)
            .field("capacity", &self.buffer.len())
            .finish()
    }
}

impl ReplyBuf {
    pub fn new(size: usize) -> Self {
        Self {
            buffer: vec![0u8; size],
            filled: 0,
        }
    }

    /// Get the filled portion of the buffer.
    pub fn filled_data(&self) -> &[u8] {
        &self.buffer[..self.filled]
    }

    /// Write a dirent header + name + zero-padding into `buf`, returning the total entry size.
    fn write_dirent(buf: &mut [u8], dirent: &FuseDirent, name_bytes: &[u8]) -> usize {
        let entry_size = protocol::fuse_dirent_size(name_bytes.len());
        buf[..FUSE_DIRENT_HEADER_SIZE].copy_from_slice(as_bytes(dirent));
        buf[FUSE_DIRENT_HEADER_SIZE..FUSE_DIRENT_HEADER_SIZE + name_bytes.len()]
            .copy_from_slice(name_bytes);
        buf[FUSE_DIRENT_HEADER_SIZE + name_bytes.len()..entry_size].fill(0);
        entry_size
    }

    /// Add a readdir entry (plain `fuse_dirent`).
    pub fn add_readdir(&mut self, name: &CStr, attr: &libc::stat, next: u64) -> ReplyBufState {
        let name_bytes = name.to_bytes();
        let entry_size = protocol::fuse_dirent_size(name_bytes.len());

        if self.filled + entry_size > self.buffer.len() {
            return ReplyBufState::Full;
        }

        let dirent = FuseDirent {
            ino: attr.st_ino,
            off: next,
            namelen: name_bytes.len() as u32,
            typ: mode_to_dirent_type(attr.st_mode),
        };

        let buf = &mut self.buffer[self.filled..];
        self.filled += Self::write_dirent(buf, &dirent, name_bytes);
        ReplyBufState::Ok
    }

    /// Add a readdirplus entry (`fuse_entry_out` + `fuse_dirent`).
    pub fn add_readdir_plus(
        &mut self,
        name: &CStr,
        entry: &EntryParam,
        next: u64,
    ) -> ReplyBufState {
        let name_bytes = name.to_bytes();
        let entry_size = protocol::fuse_direntplus_size(name_bytes.len());

        if self.filled + entry_size > self.buffer.len() {
            return ReplyBufState::Full;
        }

        let entry_out = protocol::entry_out_from_param(entry);
        let dirent = FuseDirent {
            ino: entry.attr.st_ino,
            off: next,
            namelen: name_bytes.len() as u32,
            typ: mode_to_dirent_type(entry.attr.st_mode),
        };

        let buf = &mut self.buffer[self.filled..];
        buf[..FUSE_ENTRY_OUT_SIZE].copy_from_slice(as_bytes(&entry_out));
        self.filled += FUSE_ENTRY_OUT_SIZE
            + Self::write_dirent(&mut buf[FUSE_ENTRY_OUT_SIZE..], &dirent, name_bytes);
        ReplyBufState::Ok
    }
}
