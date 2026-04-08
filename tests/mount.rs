//! Integration test: mount a minimal read-only filesystem, verify basic operations, unmount.
//!
//! This test requires `/dev/fuse` and `fusermount3`. Run with:
//!
//!     cargo test --test mount -- --ignored
//!
//! If `/dev/fuse` is not accessible, the test will be skipped (not failed).

use std::ffi::{CString, OsStr};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::{io, mem};

use futures::stream::TryStreamExt;

use proxmox_fuse::requests::FuseRequest;
use proxmox_fuse::sys::EntryParam;
use proxmox_fuse::{Fuse, Request};

const ROOT_INO: u64 = 1;
const FILE_INO: u64 = 2;
const FILE_NAME: &str = "hello.txt";
const FILE_DATA: &[u8] = b"Hello from proxmox-fuse integration test!\n";

fn root_attr() -> libc::stat {
    let mut st: libc::stat = unsafe { mem::zeroed() };
    st.st_ino = ROOT_INO;
    st.st_mode = libc::S_IFDIR | 0o755;
    st.st_nlink = 2;
    st
}

fn file_attr() -> libc::stat {
    let mut st: libc::stat = unsafe { mem::zeroed() };
    st.st_ino = FILE_INO;
    st.st_mode = libc::S_IFREG | 0o444;
    st.st_nlink = 1;
    st.st_size = FILE_DATA.len() as i64;
    st
}

async fn handle_requests(fuse: Fuse) -> io::Result<()> {
    fuse.try_for_each(|request| async move {
        match request {
            Request::Lookup(req) => {
                if req.parent == ROOT_INO && req.file_name == FILE_NAME {
                    let entry = EntryParam::simple(FILE_INO, file_attr());
                    let _ = req.reply(&entry);
                } else {
                    req.fail(libc::ENOENT)?;
                }
            }
            Request::Forget(req) => {
                req.reply();
            }
            Request::Getattr(req) => {
                let attr = match req.inode {
                    ROOT_INO => root_attr(),
                    FILE_INO => file_attr(),
                    _ => return req.fail(libc::ENOENT),
                };
                req.reply(&attr, f64::MAX)?;
            }
            Request::Readdir(mut req) => {
                if req.offset == 0 {
                    if req.add_entry(OsStr::new("."), &root_attr(), 1)?.is_full() {
                        return req.reply();
                    }
                    if req.add_entry(OsStr::new(".."), &root_attr(), 2)?.is_full() {
                        return req.reply();
                    }
                    if req
                        .add_entry(OsStr::new(FILE_NAME), &file_attr(), 3)?
                        .is_full()
                    {
                        return req.reply();
                    }
                }
                req.reply()?;
            }
            Request::Open(req) => {
                if req.inode == FILE_INO {
                    let _ = req.reply(0);
                } else {
                    req.fail(libc::ENOENT)?;
                }
            }
            Request::Release(req) => {
                req.reply()?;
            }
            Request::Read(req) => {
                if req.inode == FILE_INO {
                    let start = req.offset as usize;
                    let end = (start + req.size).min(FILE_DATA.len());
                    let data = FILE_DATA.get(start..end).unwrap_or(&[]);
                    req.reply(data)?;
                } else {
                    req.fail(libc::ENOENT)?;
                }
            }
            Request::Statfs(req) => {
                let mut stbuf: libc::statvfs = unsafe { mem::zeroed() };
                stbuf.f_bsize = 4096;
                stbuf.f_frsize = 4096;
                stbuf.f_blocks = 1000;
                stbuf.f_bfree = 500;
                stbuf.f_bavail = 500;
                stbuf.f_files = 100;
                stbuf.f_ffree = 50;
                stbuf.f_namemax = 255;
                req.reply(&stbuf)?;
            }
            other => {
                other.fail(libc::ENOSYS)?;
            }
        }
        Ok(())
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore] // Requires /dev/fuse and fusermount3
async fn mount_read_unmount() {
    // Check that /dev/fuse is accessible before proceeding.
    if !Path::new("/dev/fuse").exists() {
        eprintln!("skipping: /dev/fuse not available");
        return;
    }

    let mountpoint = std::env::temp_dir().join("proxmox-fuse-test");
    // Clean up any stale mount from a previous failed run.
    let _ = std::process::Command::new("fusermount3")
        .arg("-u")
        .arg("--")
        .arg(&mountpoint)
        .status();
    let _ = std::fs::remove_dir(&mountpoint);
    std::fs::create_dir(&mountpoint).expect("create mountpoint");

    let fuse = Fuse::builder("test-fuse")
        .enable_readdir()
        .enable_open()
        .enable_read()
        .enable_statfs()
        .build()
        .mount(&mountpoint)
        .expect("mount");

    // Spawn the FUSE request handler.
    let handler = tokio::spawn(handle_requests(fuse));

    // Run filesystem operations on a blocking thread to avoid deadlocking the
    // async executor that handles FUSE requests.
    let mp = mountpoint.clone();
    let test_result = tokio::task::spawn_blocking(move || -> Result<(), String> {
        // No sleep needed: the kernel blocks VFS operations until the daemon reads FUSE_INIT,
        // so the handler task always initialises before any filesystem call returns.

        // Test 1: readdir — list the mountpoint.
        let entries: Vec<_> = std::fs::read_dir(&mp)
            .map_err(|e| format!("read_dir: {e}"))?
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(entries, vec![OsStr::new(FILE_NAME)]);

        // Test 2: read file contents.
        let content = std::fs::read(mp.join(FILE_NAME)).map_err(|e| format!("read: {e}"))?;
        assert_eq!(content, FILE_DATA);

        // Test 3: stat the file.
        let metadata =
            std::fs::metadata(mp.join(FILE_NAME)).map_err(|e| format!("metadata: {e}"))?;
        assert!(metadata.is_file());
        assert_eq!(metadata.len(), FILE_DATA.len() as u64);

        // Test 4: non-existent file returns error.
        assert!(std::fs::metadata(mp.join("nope")).is_err());

        // Test 5: statfs.
        let c_path = CString::new(mp.as_os_str().as_bytes()).unwrap();
        let mut stbuf: libc::statvfs = unsafe { mem::zeroed() };
        let rc = unsafe { libc::statvfs(c_path.as_ptr(), &mut stbuf) };
        assert_eq!(rc, 0, "statvfs failed: {}", io::Error::last_os_error());
        assert_eq!(stbuf.f_bsize, 4096);
        assert_eq!(stbuf.f_blocks, 1000);
        assert_eq!(stbuf.f_bfree, 500);
        assert_eq!(stbuf.f_files, 100);
        assert_eq!(stbuf.f_ffree, 50);
        assert_eq!(stbuf.f_namemax, 255);

        // Unmount.
        let status = std::process::Command::new("fusermount3")
            .arg("-u")
            .arg("--")
            .arg(&mp)
            .status()
            .map_err(|e| format!("fusermount3: {e}"))?;
        assert!(status.success(), "fusermount3 -u failed");

        Ok(())
    })
    .await
    .expect("test thread panicked");
    test_result.expect("test failed");

    // The handler should complete after unmount.
    let result = handler.await.expect("handler panicked");
    assert!(result.is_ok(), "handler returned error: {result:?}");

    // Clean up.
    let _ = std::fs::remove_dir(&mountpoint);
}
