// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, bail, Context, Result};
use filetime::FileTime;
use futures::StreamExt;
use log::{debug, warn};
use nix::libc::timeval;
use nix::sys::stat::{mknod, Mode, SFlag};
use thiserror::Error;

use std::{
    collections::HashMap,
    convert::TryInto,
    ffi::CString,
    fs::Permissions,
    io,
    os::{
        fd::{AsFd, AsRawFd},
        unix::fs::PermissionsExt,
    },
    path::{Path, PathBuf},
};
use tokio::{fs, io::AsyncRead};
use tokio_tar::ArchiveBuilder;
use xattr::FileExt;

pub type UnpackResult<T> = std::result::Result<T, UnpackError>;

#[derive(Error, Debug)]
pub enum UnpackError {
    #[error("Failed to delete existing broken layer when unpacking")]
    DeleteExistingLayerFailed {
        #[source]
        source: io::Error,
    },

    #[error("Create layer directory failed")]
    CreateLayerDirectoryFailed {
        #[source]
        source: io::Error,
    },

    #[error("Failed to read entries from the tar")]
    ReadTarEntriesFailed {
        #[source]
        source: io::Error,
    },

    #[error("Illegal entry name in the layer tar: {0}")]
    IllegalEntryName(String),

    #[error("Failed to get a legal UID of the file")]
    IllegalUid {
        #[source]
        source: anyhow::Error,
    },

    #[error("Failed to get a legal GID of the file")]
    IllegalGid {
        #[source]
        source: anyhow::Error,
    },

    #[error("Failed to get a legal mtime of the file")]
    IllegalMtime {
        #[source]
        source: io::Error,
    },

    #[error("Convert whiteout file failed: {source}")]
    ConvertWhiteoutFailed {
        #[source]
        source: anyhow::Error,
    },

    #[error("Failed to unpack layer to destination")]
    UnpackFailed {
        #[source]
        source: io::Error,
    },

    #[error("Failed to set ownership for path: {path}")]
    SetOwnershipsFailed {
        #[source]
        source: anyhow::Error,
        path: String,
    },

    #[error("Failed to set file mtime: {path}")]
    SetMTimeFailed {
        #[source]
        source: anyhow::Error,
        path: String,
    },
}

// TODO: Add unit tests for both xattr supporting case and
// non-supporting case.
fn is_attr_available(path: &Path) -> bool {
    let Ok(dest) = std::fs::File::open(path) else {
        return false;
    };
    match dest.set_xattr("user.overlay.origin", b"") {
        Ok(_) => {
            debug!("xattrs supported for {path:?}");
            true
        }
        Err(e) => {
            debug!("xattrs is not supported for {path:?}, because {e:?}");
            false
        }
    }
}

const WHITEOUT_PREFIX: &str = ".wh.";
const WHITEOUT_OPAQUE_DIR: &str = ".wh..wh..opq";

/// Returns whether the file name is a whiteout file
fn is_whiteout(name: &str) -> bool {
    name.starts_with(WHITEOUT_PREFIX)
}

/// Converts a whiteout file or opaque directory.
///
/// Regular deletion whiteouts only need mknod() and work without xattr.
/// Opaque directory whiteouts require xattr to set trusted.overlay.opaque.
///
/// See OverlayFS and Aufs documentation for details:
/// https://www.kernel.org/doc/Documentation/filesystems/overlayfs.txt
/// https://aufs.sourceforge.net/aufs.html
async fn convert_whiteout(
    name: &str,
    path: &Path,
    uid: u32,
    gid: u32,
    mode: Option<u32>,
    destination: &Path,
    attr_available: bool,
) -> Result<()> {
    let parent = path
        .parent()
        .ok_or(anyhow!("Invalid whiteout parent for path: {:?}", path))?;

    // Handle opaque directories
    if name == WHITEOUT_OPAQUE_DIR {
        // Opaque directory whiteout requires xattr support
        if !attr_available {
            debug!(
                "Skipping opaque directory whiteout (xattr unavailable) for: {:?}",
                destination.join(parent)
            );
            return Ok(());
        }

        let destination_parent = destination.join(parent);
        // Setting trusted.* xattrs requires CAP_SYS_ADMIN (typically root only)
        if let Err(e) = xattr::set(&destination_parent, "trusted.overlay.opaque", b"y") {
            let current_uid = unsafe { nix::libc::getuid() };
            if current_uid != 0 && e.raw_os_error() == Some(nix::libc::EPERM) {
                warn!(
                    "Skipping opaque directory whiteout for {:?} (requires root privileges): {}",
                    destination_parent, e
                );
                return Ok(());
            } else {
                return Err(e.into());
            }
        }
        return Ok(());
    }

    // Handle whiteout files
    let original_name = name
        .strip_prefix(WHITEOUT_PREFIX)
        .ok_or(anyhow!("Failed to strip whiteout prefix for: {}", name))?;
    let original_path = parent.join(original_name);
    let path = CString::new(format!(
        "{}/{}",
        destination.display(),
        original_path.display()
    ))?;

    let path_str = path.to_string_lossy().into_owned();
    let path_buf = PathBuf::from(path_str);
    if let Some(parent) = path_buf.parent() {
        fs::create_dir_all(parent).await?;
    }

    // mknod requires CAP_MKNOD capability (typically root only)
    // If we don't have permission, skip whiteout file creation with a warning
    let current_uid = unsafe { nix::libc::getuid() };
    if let Err(e) = mknod(path.as_c_str(), SFlag::S_IFCHR, Mode::empty(), 0) {
        // Allow EPERM (Operation not permitted) errors when not running as root
        if current_uid != 0 && (e == nix::errno::Errno::EPERM || e == nix::errno::Errno::EACCES) {
            warn!(
                "Skipping whiteout file creation for {:?} (requires root privileges): {}",
                path, e
            );
            return Ok(());
        } else {
            return Err(e.into());
        }
    }

    // If we're not running as root and ownership change would fail, skip it
    if current_uid != 0 && (uid != current_uid || gid != unsafe { nix::libc::getgid() }) {
        warn!(
            "Skipping ownership change for whiteout file {:?} (not running as root)",
            path
        );
        return Ok(());
    }

    set_perms_ownerships(&path, ChownType::LChown, uid, gid, mode).await
}

/// Unpack the contents of tarball to the destination path
pub async fn unpack<R: AsyncRead + Unpin>(input: R, destination: &Path) -> UnpackResult<()> {
    if destination.exists() {
        warn!(
            "unpack destination {destination:?} already exists, will delete and rerwrite the layer",
        );
        fs::remove_dir_all(destination)
            .await
            .map_err(|source| UnpackError::DeleteExistingLayerFailed { source })?;
    }

    fs::create_dir_all(destination)
        .await
        .map_err(|source| UnpackError::CreateLayerDirectoryFailed { source })?;

    let attr_available = is_attr_available(destination);
    let mut archive = ArchiveBuilder::new(input)
        .set_ignore_zeros(true)
        .set_unpack_xattrs(attr_available)
        .set_preserve_permissions(true)
        .build();

    let mut entries = archive
        .entries()
        .map_err(|source| UnpackError::ReadTarEntriesFailed { source })?;

    let mut dirs: HashMap<CString, [timeval; 2]> = HashMap::default();
    while let Some(file) = entries.next().await {
        let mut file = file.map_err(|source| UnpackError::ReadTarEntriesFailed { source })?;

        let entry_path = file
            .path()
            .map_err(|source| UnpackError::ReadTarEntriesFailed { source })?;
        let entry_name = entry_path.file_name().unwrap_or_default().to_str().ok_or(
            UnpackError::IllegalEntryName(entry_path.to_string_lossy().to_string()),
        )?;
        let uid = file
            .header()
            .uid()
            .map_err(|e| UnpackError::IllegalUid {
                source: anyhow!("corrupted UID in header: {e:?}"),
            })?
            .try_into()
            .map_err(|_| UnpackError::IllegalUid {
                source: anyhow!("UID too large"),
            })?;
        let gid = file
            .header()
            .gid()
            .map_err(|e| UnpackError::IllegalGid {
                source: anyhow!("corrupted GID in header: {e:?}"),
            })?
            .try_into()
            .map_err(|_| UnpackError::IllegalGid {
                source: anyhow!("GID too large"),
            })?;
        let mode = file.header().mode().ok();
        let kind = file.header().entry_type();

        if is_whiteout(entry_name) {
            convert_whiteout(
                entry_name,
                &entry_path,
                uid,
                gid,
                mode,
                destination,
                attr_available,
            )
            .await
            .map_err(|source| UnpackError::ConvertWhiteoutFailed { source })?;
            continue;
        }

        match file.unpack_in(destination).await {
            Ok(_) => {}
            Err(e) => match try_hardlink_fallback(&kind, &mut file, destination).await {
                Ok(true) => {}
                Ok(false) => return Err(UnpackError::UnpackFailed { source: e }),
                Err(f) => {
                    return Err(UnpackError::UnpackFailed {
                        source: io::Error::other(format!(
                            "Fallback failed, {f:?}, after original unpack error: {e:?}"
                        )),
                    })
                }
            },
        }

        let path = format!(
            "{}/{}",
            destination.display(),
            file.path()
                .map_err(|source| UnpackError::ReadTarEntriesFailed { source })?
                .display()
        );
        let path_cstring =
            CString::new(path.clone()).map_err(|_| UnpackError::IllegalEntryName(path.clone()))?;

        let file_path = path_cstring.to_str().expect("must be utf8");

        let mtime = file
            .header()
            .mtime()
            .map_err(|source| UnpackError::IllegalMtime { source })? as i64;

        // krata-tokio-tar crate does not provide a way to preserve permissions
        // for all kinds of files.
        //
        // this crate also does not cover symlink files/dir mtime.
        //
        // because we changed the files ownership manually, thus we need to reset
        // the mtime again.
        if kind.is_dir() || file.header().as_ustar().is_none() && file.path_bytes().ends_with(b"/")
        {
            set_perms_ownerships(&path_cstring, ChownType::LChown, uid, gid, mode)
                .await
                .map_err(|source| UnpackError::SetOwnershipsFailed { source, path })?;
            let atime = timeval {
                tv_sec: mtime,
                tv_usec: 0,
            };

            let times = [atime, atime];

            dirs.insert(path_cstring.clone(), times);
        } else if !kind.is_symlink() && !kind.is_hard_link() {
            // for other files except link we use fchown
            let f = fs::OpenOptions::new()
                .write(true)
                .open(file_path)
                .await
                .map_err(|e| UnpackError::SetOwnershipsFailed {
                    source: anyhow!("failed to open file: {e}"),
                    path: path.clone(),
                })?;

            set_perms_ownerships(&path_cstring, ChownType::FChown(f), uid, gid, mode)
                .await
                .map_err(|source| UnpackError::SetOwnershipsFailed {
                    source,
                    path: path.clone(),
                })?;

            // set mtime
            let mtime = FileTime::from_unix_time(mtime, 0);
            filetime::set_file_times(file_path, mtime, mtime).map_err(|e| {
                UnpackError::SetMTimeFailed {
                    source: e.into(),
                    path,
                }
            })?;
        }
    }

    // Directory timestamps need update after all files are extracted.
    for (k, v) in dirs.iter() {
        let ret = unsafe { nix::libc::utimes(k.as_ptr(), v.as_ptr()) };
        if ret != 0 {
            return Err(UnpackError::SetMTimeFailed {
                source: anyhow!(
                    "change directory utime error: {:?}",
                    io::Error::last_os_error(),
                ),
                path: k.to_string_lossy().to_string(),
            });
        }
    }

    Ok(())
}

enum ChownType {
    LChown,
    FChown(fs::File),
}

async fn set_perms_ownerships(
    dst: &CString,
    chown: ChownType,
    uid: u32,
    gid: u32,
    mode: Option<u32>,
) -> Result<()> {
    // Get current user's UID to check if we can change ownership
    let current_uid = unsafe { nix::libc::getuid() };

    match chown {
        ChownType::FChown(f) => {
            let ret = unsafe { nix::libc::fchown(f.as_fd().as_raw_fd(), uid, gid) };
            if ret != 0 {
                let err = io::Error::last_os_error();
                let errno = err.raw_os_error();
                // If not running as root, allow EPERM/EACCES errors when trying to change ownership
                // to a different user. This is expected behavior for non-privileged users.
                if current_uid != 0
                    && (errno == Some(nix::libc::EPERM) || errno == Some(nix::libc::EACCES))
                {
                    debug!(
                        "Skipping ownership change for {:?} (not running as root, uid={}, target uid={}, errno={:?}): {}",
                        dst, current_uid, uid, errno, err
                    );
                } else {
                    bail!(
                        "failed to set ownerships of file: {:?} chown error: {:?} (current_uid={}, errno={:?})",
                        dst,
                        err,
                        current_uid,
                        errno
                    );
                }
            }
        }
        ChownType::LChown => {
            let ret = unsafe { nix::libc::lchown(dst.as_ptr(), uid, gid) };
            if ret != 0 {
                let err = io::Error::last_os_error();
                let errno = err.raw_os_error();
                // If not running as root, allow EPERM/EACCES errors when trying to change ownership
                // to a different user. This is expected behavior for non-privileged users.
                if current_uid != 0
                    && (errno == Some(nix::libc::EPERM) || errno == Some(nix::libc::EACCES))
                {
                    debug!(
                        "Skipping ownership change for {:?} (not running as root, uid={}, target uid={}, errno={:?}): {}",
                        dst, current_uid, uid, errno, err
                    );
                } else {
                    bail!(
                        "failed to set ownerships of file: {:?} lchown error: {:?} (current_uid={}, errno={:?})",
                        dst,
                        err,
                        current_uid,
                        errno
                    );
                }
            }
        }
    }
    // ... then set permissions, SUID bits set here is kept
    if let Some(mode) = mode {
        let perm = Permissions::from_mode(mode as _);
        fs::set_permissions(Path::new(dst.to_str().expect("must be utf8")), perm)
            .await
            .context("failed to set permissions")?;
    }

    Ok(())
}

// Fallback for hard links whose linkname is absolute. Returns true if it handled the entry.
async fn try_hardlink_fallback<R: AsyncRead + Unpin>(
    kind: &tokio_tar::EntryType,
    file: &mut tokio_tar::Entry<R>,
    destination: &Path,
) -> UnpackResult<bool> {
    if !kind.is_hard_link() {
        return Ok(false);
    }

    let linkname = match file
        .link_name()
        .map_err(|source| UnpackError::ReadTarEntriesFailed { source })?
    {
        Some(cow) => cow.into_owned(),
        None => return Ok(false),
    };
    if !linkname.is_absolute() {
        return Ok(false);
    }

    let entry_rel = file
        .path()
        .map_err(|source| UnpackError::ReadTarEntriesFailed { source })?;

    // Resolve the final destination path for this entry and ensure parent exists.
    let dst_entry_abs = destination.join(&entry_rel);
    if let Some(parent) = dst_entry_abs.parent() {
        fs::create_dir_all(parent)
            .await
            .map_err(|source| UnpackError::UnpackFailed { source })?;
    }

    // Drop the leading root from linkname
    let stripped = linkname
        .strip_prefix(Path::new("/"))
        .unwrap_or(linkname.as_path());
    let anchored_src = destination.join(stripped);

    // Resolve symlinks according to the actual FS
    let dst_canon = fs::canonicalize(destination)
        .await
        .map_err(|source| UnpackError::UnpackFailed { source })?;
    let src_canon = fs::canonicalize(&anchored_src)
        .await
        .map_err(|source| UnpackError::UnpackFailed { source })?;

    if !src_canon.starts_with(&dst_canon) {
        return Err(UnpackError::UnpackFailed {
            source: std::io::Error::other("hardlink target escapes destination"),
        });
    }

    match fs::hard_link(&src_canon, &dst_entry_abs).await {
        Ok(()) => Ok(true),
        Err(e) => Err(UnpackError::UnpackFailed { source: e }),
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{chown, lchown, MetadataExt};

    use std::os::unix::fs::FileTypeExt;
    use tokio::{
        fs::{self, File},
        io::{empty, AsyncWriteExt},
    };
    use tokio_tar::{Builder, EntryType, Header};

    use super::*;

    #[tokio::test]
    async fn test_unpack() {
        let mut ar = Builder::new(Vec::new());
        let tempdir = tempfile::tempdir().unwrap();

        let path = tempdir.path().join("file.txt");
        let mut f = File::create(&path).await.unwrap();
        f.write_all(b"file data").await.unwrap();
        f.flush().await.unwrap();

        // Try to set ownership, but skip if not running as root
        let _ = chown(path.clone(), Some(10), Some(10));

        let mtime = filetime::FileTime::from_unix_time(20_000, 0);
        filetime::set_file_mtime(&path, mtime).unwrap();

        ar.append_file("file.txt", &mut File::open(&path).await.unwrap())
            .await
            .unwrap();

        let path = tempdir.path().join("link");
        tokio::fs::symlink("file.txt", &path).await.unwrap();
        let mtime = filetime::FileTime::from_unix_time(20_000, 0);
        filetime::set_file_mtime(&path, mtime).unwrap();
        // Try to set ownership, but skip if not running as root
        let _ = lchown(path.clone(), Some(10), Some(10));
        ar.append_file("link", &mut File::open(&path).await.unwrap())
            .await
            .unwrap();

        let path = tempdir
            .path()
            .join(WHITEOUT_PREFIX.to_owned() + "whiteout_file.txt");
        File::create(&path).await.unwrap();
        ar.append_file(
            WHITEOUT_PREFIX.to_owned() + "whiteout_file.txt",
            &mut File::open(&path).await.unwrap(),
        )
        .await
        .unwrap();

        let path = tempdir.path().join("dir");
        fs::create_dir(&path).await.unwrap();

        filetime::set_file_mtime(&path, mtime).unwrap();
        ar.append_path_with_name(&path, "dir").await.unwrap();

        let path = tempdir.path().join("whiteout_dir");
        fs::create_dir(&path).await.unwrap();
        ar.append_path_with_name(&path, "whiteout_dir")
            .await
            .unwrap();

        let path = tempdir
            .path()
            .join("whiteout_dir/".to_owned() + WHITEOUT_OPAQUE_DIR);
        fs::create_dir(&path).await.unwrap();
        ar.append_path_with_name(&path, "whiteout_dir/".to_owned() + WHITEOUT_OPAQUE_DIR)
            .await
            .unwrap();

        // A file inside usr/bin which the hard link will point to.
        let test_src_fs = tempdir.path().join("usr/bin/test_binary");
        fs::create_dir_all(test_src_fs.parent().unwrap())
            .await
            .unwrap();
        let mut fu = File::create(&test_src_fs).await.unwrap();
        fu.write_all(b"unzip-data").await.unwrap();
        fu.flush().await.unwrap();
        ar.append_file(
            "usr/bin/test_binary",
            &mut File::open(&test_src_fs).await.unwrap(),
        )
        .await
        .unwrap();

        let mut hdr = Header::new_gnu();
        hdr.set_entry_type(EntryType::Link); // hard link
        hdr.set_link_name("/usr/bin/test_binary").unwrap(); // absolute linkname
        hdr.set_path("usr/bin/test_binary_hardlink").unwrap(); // entry path inside the archive
        hdr.set_size(0);
        hdr.set_mode(0o644);
        hdr.set_uid(0);
        hdr.set_gid(0);
        hdr.set_mtime(20_000);
        hdr.set_cksum();
        ar.append(&hdr, empty()).await.unwrap();

        // TODO: Add more file types like symlink, char, block devices.
        let data = ar.into_inner().await.unwrap();
        tempdir.close().unwrap();

        let destination = Path::new("/tmp/image_test_dir");
        if destination.exists() {
            fs::remove_dir_all(destination).await.unwrap();
        }

        let unpack_result = unpack(data.as_slice(), destination).await;
        if let Err(ref e) = unpack_result {
            eprintln!("Unpack failed: {:?}", e);
        }
        assert!(unpack_result.is_ok());

        let current_uid = unsafe { nix::libc::getuid() };
        let is_root = current_uid == 0;

        let path = destination.join("file.txt");
        let metadata = fs::metadata(path).await.unwrap();
        let new_mtime = filetime::FileTime::from_last_modification_time(&metadata);
        assert_eq!(mtime, new_mtime);
        // Only check ownership if running as root
        if is_root {
            assert_eq!(metadata.gid(), 10);
            assert_eq!(metadata.uid(), 10);
        }

        let path = destination.join("link");
        let metadata = fs::symlink_metadata(path).await.unwrap();
        let new_mtime = filetime::FileTime::from_last_modification_time(&metadata);
        assert_eq!(mtime, new_mtime);
        // Only check ownership if running as root
        if is_root {
            assert_eq!(metadata.gid(), 10);
            assert_eq!(metadata.uid(), 10);
        }

        let attr_available = is_attr_available(destination);
        // Whiteout files require root privileges to create (mknod with CAP_MKNOD)
        if attr_available && is_root {
            let path = destination.join("whiteout_file.txt");
            let metadata = fs::metadata(path).await.unwrap();
            assert!(metadata.file_type().is_char_device());
        }

        let path = destination.join("dir");
        let metadata = fs::metadata(path).await.unwrap();
        let new_mtime = filetime::FileTime::from_last_modification_time(&metadata);
        assert_eq!(mtime, new_mtime);

        // trusted.* xattrs require root privileges
        if attr_available && is_root {
            let path = destination.join("whiteout_dir");
            let opaque = xattr::get(path, "trusted.overlay.opaque").unwrap().unwrap();
            assert_eq!(opaque, b"y");
        }

        // Validate absolute hard link has been anchored inside destination by fallback.
        let test_binary = destination.join("usr/bin/test_binary");
        let test_binary_hardlink = destination.join("usr/bin/test_binary_hardlink");
        let meta_test_binary = fs::metadata(&test_binary).await.unwrap();
        let meta_test_binary_hardlink = fs::metadata(&test_binary_hardlink).await.unwrap();
        assert!(meta_test_binary.is_file() && meta_test_binary_hardlink.is_file());
        // On Unix, hard links share the same inode and usually nlink >= 2.
        assert_eq!(meta_test_binary.ino(), meta_test_binary_hardlink.ino());

        // though destination already exists, it will be deleted
        // and rewrite
        assert!(unpack(data.as_slice(), destination).await.is_ok());
    }

    #[tokio::test]
    async fn test_unpack_rejects_escaping_absolute_hardlink() {
        let td = tempfile::tempdir().unwrap();
        let outside_file = td.path().join("outside_file");
        let mut f = File::create(&outside_file).await.unwrap();
        f.write_all(b"outside-data").await.unwrap();
        f.flush().await.unwrap();

        // linkname = "/../outside_file" will be anchored in fallback mode as
        // destination/../outside_file, which points to the parent directory of the destination.
        let mut ar = Builder::new(Vec::new());
        let mut hdr = Header::new_gnu();
        hdr.set_entry_type(EntryType::Link);
        hdr.set_link_name("/../outside_file").unwrap();
        hdr.set_path("subdir/evil_hardlink").unwrap();
        hdr.set_size(0);
        hdr.set_mode(0o644);
        hdr.set_uid(0);
        hdr.set_gid(0);
        hdr.set_mtime(20_000);
        hdr.set_cksum();
        ar.append(&hdr, empty()).await.unwrap();

        let data = ar.into_inner().await.unwrap();

        let destination = td.path().join("dest");
        let res = unpack(data.as_slice(), &destination).await;

        // Expectation: unpacking should fail due to anti-escape check
        match res {
            Err(UnpackError::UnpackFailed { source }) => {
                assert!(
                    source
                        .to_string()
                        .contains("hardlink target escapes destination"),
                    "unexpected error: {source}"
                );
            }
            Ok(_) => panic!("unpack unexpectedly succeeded; anti-escape check failed"),
            Err(e) => panic!("unexpected error variant: {e:?}"),
        }

        // Confirm that the escaping hardlink was not created
        let evil_path = destination.join("subdir/evil_hardlink");
        assert!(fs::metadata(&evil_path).await.is_err());
    }
}
