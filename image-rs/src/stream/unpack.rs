// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, bail, Context, Result};
use filetime::FileTime;
use futures::StreamExt;
use nix::libc;
use nix::libc::timeval;
use pathrs::flags::OpenFlags;
use pathrs::InodeType;
use thiserror::Error;
use tracing::{debug, warn};

use std::{
    collections::HashMap,
    convert::TryInto,
    ffi::CString,
    fs::Permissions,
    io,
    os::{
        fd::{AsFd, AsRawFd, BorrowedFd},
        unix::fs::PermissionsExt,
    },
    path::Path,
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

    #[error("pathrs error: {source}")]
    PathRsFailed {
        #[source]
        source: pathrs::error::Error,
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
    layer_dir: &Path,
    attr_available: bool,
) -> Result<()> {
    let parent = path
        .parent()
        .ok_or(anyhow!("Invalid whiteout parent for path: {:?}", path))?;

    let layer_dir = pathrs::Root::open(layer_dir).context("Failed initialize layer dir")?;

    // Handle opaque directories
    if name == WHITEOUT_OPAQUE_DIR {
        let opaque_dir = layer_dir.resolve(parent)?;

        // Opaque directory whiteout requires xattr support
        if !attr_available {
            debug!(
                "Skipping opaque directory whiteout (xattr unavailable) for: {:?}",
                opaque_dir
            );
            return Ok(());
        }

        let opaque_dir = opaque_dir.reopen(OpenFlags::O_RDONLY)?;
        opaque_dir.set_xattr("trusted.overlay.opaque", b"y")?;

        return Ok(());
    }

    // Handle whiteout files
    let original_name = name
        .strip_prefix(WHITEOUT_PREFIX)
        .ok_or(anyhow!("Failed to strip whiteout prefix for: {}", name))?;
    let original_path = parent.join(original_name);

    if let Some(parent) = original_path.parent() {
        layer_dir.mkdir_all(parent, &Permissions::from_mode(0o755))?;
    }

    layer_dir.create(
        &original_path,
        &InodeType::CharacterDevice(Permissions::from_mode(0o000), 0),
    )?;

    Ok(())
}

/// Unpack the contents of tarball to the layer_dir path
pub async fn unpack<R: AsyncRead + Unpin>(input: R, layer_dir: &Path) -> UnpackResult<()> {
    if layer_dir.exists() {
        warn!("layer_dir {layer_dir:?} already exists, will delete and rewrite the layer",);
        fs::remove_dir_all(layer_dir)
            .await
            .map_err(|source| UnpackError::DeleteExistingLayerFailed { source })?;
    }

    fs::create_dir_all(layer_dir)
        .await
        .map_err(|source| UnpackError::CreateLayerDirectoryFailed { source })?;

    let attr_available = is_attr_available(layer_dir);
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
            convert_whiteout(entry_name, &entry_path, layer_dir, attr_available)
                .await
                .map_err(|source| UnpackError::ConvertWhiteoutFailed { source })?;
            continue;
        }

        // Both of these paths ensure that the entry is actually inside the layer dir
        if let Err(e) = file.unpack_in(layer_dir).await {
            match try_hardlink_fallback(&kind, &mut file, layer_dir).await {
                Ok(true) => {}
                Ok(false) => return Err(UnpackError::UnpackFailed { source: e }),
                Err(f) => {
                    return Err(UnpackError::UnpackFailed {
                        source: io::Error::other(format!(
                            "Fallback failed, {f:?}, after original unpack error: {e:?}"
                        )),
                    })
                }
            }
        }

        let path = format!(
            "{}/{}",
            layer_dir.display(),
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
        if kind.is_dir()
            || file.header().as_ustar().is_none()
                && file
                    .path_bytes()
                    .map_err(|source| UnpackError::ReadTarEntriesFailed { source })?
                    .ends_with(b"/")
        {
            let f =
                std::fs::File::open(file_path).map_err(|e| UnpackError::SetOwnershipsFailed {
                    source: anyhow!("failed to open dir: {e}"),
                    path: path.clone(),
                })?;

            set_permissions(f.as_fd(), uid, gid, mode)
                .map_err(|source| UnpackError::SetOwnershipsFailed { source, path })?;
            let atime = timeval {
                tv_sec: mtime,
                tv_usec: 0,
            };

            let times = [atime, atime];

            dirs.insert(path_cstring.clone(), times);
        } else if !kind.is_symlink() && !kind.is_hard_link() {
            let f = fs::OpenOptions::new()
                .write(true)
                .open(file_path)
                .await
                .map_err(|e| UnpackError::SetOwnershipsFailed {
                    source: anyhow!("failed to open file: {e}"),
                    path: path.clone(),
                })?;

            set_permissions(f.as_fd(), uid, gid, mode).map_err(|source| {
                UnpackError::SetOwnershipsFailed {
                    source,
                    path: path.clone(),
                }
            })?;

            // set mtime
            let mtime = FileTime::from_unix_time(mtime, 0);
            filetime::set_file_times(file_path, mtime, mtime).map_err(|e| {
                UnpackError::SetMTimeFailed {
                    source: e.into(),
                    path,
                }
            })?;
        } else if kind.is_symlink() {
            let path_cstr =
                CString::new(file_path).map_err(|_| UnpackError::IllegalEntryName(path.clone()))?;
            let ret = unsafe { libc::lchown(path_cstr.as_ptr(), uid, gid) };

            if ret != 0 {
                return Err(UnpackError::SetOwnershipsFailed {
                    source: io::Error::last_os_error().into(),
                    path: path.clone(),
                });
            }
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

fn set_permissions(fd: BorrowedFd<'_>, uid: u32, gid: u32, mode: Option<u32>) -> Result<()> {
    let ret =
        unsafe { libc::fchownat(fd.as_raw_fd(), c"".as_ptr(), uid, gid, libc::AT_EMPTY_PATH) };
    if ret != 0 {
        bail!("failed to set ownership: {:?}", io::Error::last_os_error());
    }

    if let Some(mode) = mode {
        let ret = unsafe { libc::fchmod(fd.as_raw_fd(), mode as libc::mode_t) };
        if ret != 0 {
            bail!(
                "failed to set permissions: {:?}",
                io::Error::last_os_error()
            );
        }
    }

    Ok(())
}

/// Try creating a hardlink with an absolute link name/target.
/// Returns Ok(True) if the hardlink is created.
async fn try_hardlink_fallback<R: AsyncRead + Unpin>(
    kind: &tokio_tar::EntryType,
    file: &mut tokio_tar::Entry<R>,
    layer_dir: &Path,
) -> UnpackResult<bool> {
    if !kind.is_hard_link() {
        return Ok(false);
    }

    // With tar archives, the link name refers to the file that
    // the hard link is pointing to.
    // This is the opposite of how the term is used with ln.
    let link_target = match file
        .link_name()
        .map_err(|source| UnpackError::ReadTarEntriesFailed { source })?
    {
        Some(cow) => cow.into_owned(),
        None => return Ok(false),
    };
    if !link_target.is_absolute() {
        return Ok(false);
    }

    // Hardlinks may not exit the layer dir.
    let layer_dir =
        pathrs::Root::open(layer_dir).map_err(|source| UnpackError::PathRsFailed { source })?;

    let link_path = file
        .path()
        .map_err(|source| UnpackError::ReadTarEntriesFailed { source })?;

    // Create parent directories for the link path (link target must already exist)
    if let Some(parent) = link_path.parent() {
        layer_dir
            .mkdir_all(parent, &Permissions::from_mode(0o755))
            .map_err(|source| UnpackError::PathRsFailed { source })?;
    }

    layer_dir
        .create(&link_path, &InodeType::Hardlink(link_target.to_path_buf()))
        .map_err(|source| UnpackError::PathRsFailed { source })?;

    Ok(true)
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

    use rstest::rstest;

    use super::*;

    #[tokio::test]
    #[cfg_attr(target_arch = "s390x", ignore)]
    async fn test_unpack() {
        let mut ar = Builder::new(Vec::new());
        let tempdir = tempfile::tempdir().unwrap();

        let path = tempdir.path().join("file.txt");
        let mut f = File::create(&path).await.unwrap();
        f.write_all(b"file data").await.unwrap();
        f.flush().await.unwrap();

        chown(path.clone(), Some(10), Some(10)).unwrap();

        let mtime = filetime::FileTime::from_unix_time(20_000, 0);
        filetime::set_file_mtime(&path, mtime).unwrap();

        ar.append_file("file.txt", &mut File::open(&path).await.unwrap())
            .await
            .unwrap();

        let path = tempdir.path().join("link");
        tokio::fs::symlink("file.txt", &path).await.unwrap();
        let mtime = filetime::FileTime::from_unix_time(20_000, 0);
        filetime::set_file_mtime(&path, mtime).unwrap();
        lchown(path.clone(), Some(10), Some(10)).unwrap();
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

        assert!(unpack(data.as_slice(), destination).await.is_ok());

        let path = destination.join("file.txt");
        let metadata = fs::metadata(path).await.unwrap();
        let new_mtime = filetime::FileTime::from_last_modification_time(&metadata);
        assert_eq!(mtime, new_mtime);
        assert_eq!(metadata.gid(), 10);
        assert_eq!(metadata.uid(), 10);

        let path = destination.join("link");
        let metadata = fs::symlink_metadata(path).await.unwrap();
        let new_mtime = filetime::FileTime::from_last_modification_time(&metadata);
        assert_eq!(mtime, new_mtime);
        assert_eq!(metadata.gid(), 10);
        assert_eq!(metadata.uid(), 10);

        let attr_available = is_attr_available(destination);
        if attr_available {
            let path = destination.join("whiteout_file.txt");
            let metadata = fs::metadata(path).await.unwrap();
            assert!(metadata.file_type().is_char_device());
        }

        let path = destination.join("dir");
        let metadata = fs::metadata(path).await.unwrap();
        let new_mtime = filetime::FileTime::from_last_modification_time(&metadata);
        assert_eq!(mtime, new_mtime);

        if attr_available {
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

    #[rstest]
    #[case::absolute_link_target("/etc/os-release", true)]
    #[case::relative_escape_link_target("../../etc/os-release", false)]
    #[tokio::test]
    async fn test_unpack_hardlink_tar_cases(#[case] link_name: &str, #[case] expect_ok: bool) {
        let td = tempfile::tempdir().unwrap();
        let mut ar = Builder::new(Vec::new());

        // 1. Create a file, write content, add it to the archive as the link target.
        let source_file = td.path().join("os-release");
        let mut f = File::create(&source_file).await.unwrap();
        f.write_all(b"test-data\n").await.unwrap();
        f.flush().await.unwrap();
        ar.append_file(
            "etc/os-release",
            &mut File::open(&source_file).await.unwrap(),
        )
        .await
        .unwrap();

        // 2. Append a hardlink entry with case-provided link target.
        let link_entry_path = "etc/os-release.hardlink";

        let mut hdr = Header::new_gnu();
        hdr.set_entry_type(EntryType::Link);
        hdr.set_link_name(link_name).unwrap();
        hdr.set_path(link_entry_path).unwrap();
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

        // 3. Assert unpack outcome and resulting paths under destination.
        let hardlink_path = destination.join(link_entry_path);
        if expect_ok {
            res.unwrap();
            let target = destination.join("etc/os-release");
            let target_meta = fs::metadata(&target).await.unwrap();
            let hardlink_meta = fs::metadata(&hardlink_path).await.unwrap();
            assert!(target_meta.is_file() && hardlink_meta.is_file());
            assert_eq!(target_meta.ino(), hardlink_meta.ino());
        } else {
            assert!(
                res.is_err(),
                "unpack should fail when hardlink target resolves outside the layer root: {res:?}"
            );
            assert!(
                fs::metadata(&hardlink_path).await.is_err(),
                "hardlink entry must not be created under destination"
            );
        }
    }
}
