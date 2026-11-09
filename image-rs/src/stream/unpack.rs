// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result, anyhow, bail};
use filetime::FileTime;
use nix::libc;
use nix::libc::timeval;
use nix::sys::{
    stat::{UtimensatFlags, utimensat},
    time::TimeSpec,
};
use pathrs::{InodeType, Root, flags::OpenFlags};
use tar_framing::{
    ArchiveFormat, PaxKeyword, PaxRecord, PaxValue, StreamPolicy, UstarKind,
    logical::{MemberExtensions, MemberFrame, TarReader},
};
use thiserror::Error;
use tracing::{debug, warn};

use std::{
    collections::HashMap,
    convert::TryInto,
    ffi::{CString, OsStr},
    fs::Permissions,
    io,
    os::{
        fd::{AsFd, AsRawFd, BorrowedFd},
        unix::{ffi::OsStrExt, fs::PermissionsExt},
    },
    path::{Component, Path, PathBuf},
};
use tokio::{
    fs,
    io::{AsyncRead, AsyncWriteExt},
};
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

    #[error("Failed to set permissions for path: {path}")]
    SetPermissionsFailed {
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

/// The chunk size for reading the payload of the tar entry.
const PAYLOAD_CHUNK_BYTES: usize = 128 * 1024;

/// Creation modes before the header mode is applied, subject to the process
/// umask. These match `std::fs` defaults used by tokio-tar.
const CREATE_FILE_MODE: u32 = 0o666;
const CREATE_DIR_MODE: u32 = 0o777;

/// The mode mask is used to mask the mode of the file or directory.
const MODE_MASK: u32 = 0o7777;

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

/// Returns whether the tar entry names the layer root directory itself.
///
/// OCI image layers may include a `.` entry to carry the root directory metadata.
/// The layer extraction directory already exists, so this entry must not be unpacked
/// again; only its ownership and timestamps are applied at the end.
fn is_layer_root_entry(path: &Path) -> bool {
    path.as_os_str().is_empty() || path == Path::new(".") || path == Path::new("./")
}

/// Returns whether the tar entry should be treated as a directory when applying
/// ownership, mode, and deferred mtime after unpack.
///
/// OCI layer tars are usually ustar or PAX. In those formats, directories are
/// identified by typeflag `5` ([`UstarKind::Directory`]).
///
/// Headers without the POSIX ustar magic do not carry a reliable directory
/// typeflag; there, a trailing `/` on the path name historically meant
/// "directory". tar-framing rejects v7 headers, so the only such headers left
/// are GNU ones. This matches `tokio_tar::Entry::unpack` ("Old BSD-tar
/// compatibility"), where `Header::as_ustar` is `None` for GNU headers.
fn is_dir(kind: UstarKind, format: ArchiveFormat, path_bytes: &[u8]) -> bool {
    kind == UstarKind::Directory || (format == ArchiveFormat::Gnu && path_bytes.ends_with(b"/"))
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

/// Unpack a layer tarball into `layer_dir`.
///
/// Decoded via tar-framing (tar-codec's engine). `Archive::extract_in` is not
/// used: it drops uid/gid/mtime, normalizes modes, rejects specials, and does
/// not restore vendor xattrs or overlay whiteouts.
///
/// TODO: refactor the logic once https://github.com/astral-sh/astral-codec/issues/308 is resolved
///
/// | entry type                         | uid/gid | mode        | mtime       |
/// |------------------------------------|---------|-------------|-------------|
/// | whiteout                           | -       | us (0o000)  | -           |
/// | layer root "."                     | us      | us          | defer       |
/// | directory                          | us      | us          | defer       |
/// | symlink                            | us      | -           | us          |
/// | hard link                          | us      | -           | us          |
/// | regular file / fifo / char / block | us      | us          | us          |
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

    let layer_root =
        Root::open(layer_dir).map_err(|source| UnpackError::PathRsFailed { source })?;

    let attr_available = is_attr_available(layer_dir);
    let mut archive = TarReader::new(input)
        .with_policy(StreamPolicy::default().allow_header_uname_and_gname_without_terminator(true));
    let mut chunk = Vec::new();

    let mut dirs: HashMap<PathBuf, i64> = HashMap::default();
    let mut root_times: Option<[timeval; 2]> = None;
    while let Some(file) =
        archive
            .next_frame()
            .await
            .map_err(|source| UnpackError::ReadTarEntriesFailed {
                source: io::Error::other(source),
            })?
    {
        // 1. collect the entry path, name, uid, gid, mode, and mtime
        let path_bytes = file
            .effective_path()
            .map_err(|source| UnpackError::ReadTarEntriesFailed {
                source: io::Error::other(source),
            })?
            .into_owned();
        let entry_path = layer_relative_path(Path::new(OsStr::from_bytes(&path_bytes)));
        let entry_name = entry_path.file_name().unwrap_or_default().to_str().ok_or(
            UnpackError::IllegalEntryName(entry_path.to_string_lossy().to_string()),
        )?;
        let uid = owner_id(
            file.header.uid,
            &file.extensions,
            PaxKeyword::Uid,
            "UID",
            |e| UnpackError::IllegalUid { source: e },
        )?;
        let gid = owner_id(
            file.header.gid,
            &file.extensions,
            PaxKeyword::Gid,
            "GID",
            |e| UnpackError::IllegalGid { source: e },
        )?;
        let mode = file.header.mode.map(|mode| (mode as u32) & MODE_MASK);
        let kind = file.header.kind;
        // ustar/GNU header mtime only. Pax `mtime` is not applied.
        let mtime = file.header.mtime.ok_or_else(|| UnpackError::IllegalMtime {
            source: io::Error::other("corrupted mtime in header"),
        })? as i64;

        // 2. whiteout: tar-framing does not handle overlay whiteouts.
        if is_whiteout(entry_name) {
            convert_whiteout(entry_name, &entry_path, layer_dir, attr_available)
                .await
                .map_err(|source| UnpackError::ConvertWhiteoutFailed { source })?;
            continue;
        }

        let is_dir = is_dir(kind, file.header.format, &path_bytes);

        // 3. layer root ".": do not unpack; apply ownership and mode, defer mtime.
        if is_layer_root_entry(&entry_path) {
            if is_dir {
                let path = layer_dir.display().to_string();
                fchown_at(layer_root.as_fd(), uid, gid).map_err(|source| {
                    UnpackError::SetOwnershipsFailed {
                        source,
                        path: path.clone(),
                    }
                })?;
                if let Some(mode) = mode {
                    fchmodat(layer_root.as_fd(), mode).map_err(|source| {
                        UnpackError::SetPermissionsFailed {
                            source: source.context("failed to set permissions for layer root"),
                            path,
                        }
                    })?;
                }
                root_times = Some(dir_times(mtime));
            } else {
                warn!(
                    "skipping layer root tar entry {:?}: not a directory (type {:?})",
                    entry_path, kind
                );
            }
            continue;
        }

        // 4. unpack the entry to the layer directory
        // Like tokio-tar's `unpack_in`, an entry whose path contains a `..`
        // component is silently not extracted, and unpacking continues.
        if entry_path
            .components()
            .any(|c| matches!(c, Component::ParentDir))
        {
            continue;
        }
        extract_entry(
            file,
            &layer_root,
            &entry_path,
            is_dir,
            attr_available,
            &mut chunk,
        )
        .await?;

        // 5. apply ownership / mode / mtime (see `unpack` doc comment for per-type details).
        let err_path = layer_dir.join(&entry_path).display().to_string();

        if is_dir {
            let handle = layer_root
                .resolve(&entry_path)
                .map_err(|source| UnpackError::PathRsFailed { source })?;
            fchown_at(handle.as_fd(), uid, gid).map_err(|source| {
                UnpackError::SetOwnershipsFailed {
                    source,
                    path: err_path.to_string(),
                }
            })?;
            if let Some(mode) = mode {
                fchmodat(handle.as_fd(), mode).map_err(|source| {
                    UnpackError::SetPermissionsFailed {
                        source,
                        path: err_path.to_string(),
                    }
                })?;
            }
            dirs.insert(entry_path, mtime);
        } else if kind == UstarKind::SymbolicLink {
            let handle = layer_root
                .resolve_nofollow(&entry_path)
                .map_err(|source| UnpackError::PathRsFailed { source })?;
            fchown_at(handle.as_fd(), uid, gid).map_err(|source| {
                UnpackError::SetOwnershipsFailed {
                    source,
                    path: err_path.to_string(),
                }
            })?;
            set_times(&layer_root, layer_dir, &entry_path, mtime)?;
        } else if kind == UstarKind::HardLink {
            let handle = layer_root
                .resolve(&entry_path)
                .map_err(|source| UnpackError::PathRsFailed { source })?;
            fchown_at(handle.as_fd(), uid, gid).map_err(|source| {
                UnpackError::SetOwnershipsFailed {
                    source,
                    path: err_path.to_string(),
                }
            })?;
            set_times(&layer_root, layer_dir, &entry_path, mtime)?;
        } else {
            let handle = layer_root
                .resolve(&entry_path)
                .map_err(|source| UnpackError::PathRsFailed { source })?;
            fchown_at(handle.as_fd(), uid, gid).map_err(|source| {
                UnpackError::SetOwnershipsFailed {
                    source,
                    path: err_path.to_string(),
                }
            })?;
            if let Some(mode) = mode {
                fchmodat(handle.as_fd(), mode).map_err(|source| {
                    UnpackError::SetPermissionsFailed {
                        source,
                        path: err_path.to_string(),
                    }
                })?;
            }
            set_times(&layer_root, layer_dir, &entry_path, mtime)?;
        }
    }

    // Directory timestamps need update after all files are extracted.
    for (path, mtime) in dirs.iter() {
        set_times(&layer_root, layer_dir, path, *mtime)?;
    }

    // The layer root directory is created before unpacking and is modified while
    // entries are extracted; apply the root entry timestamps last.
    if let Some(times) = root_times {
        let path = layer_dir.display().to_string();
        let ft = FileTime::from_unix_time(times[1].tv_sec, 0);
        filetime::set_file_times(layer_dir, ft, ft).map_err(|e| UnpackError::SetMTimeFailed {
            source: e.into(),
            path,
        })?;
    }

    Ok(())
}

/// Creates `path` inside the layer from a tar member, in place of tokio-tar's
/// `Entry::unpack_in`. Ownership, mode and mtime are applied by the caller.
///
/// All paths are resolved by pathrs inside `layer_root`. As with tokio-tar, an
/// existing file or symlink is replaced, an existing directory is kept, hard
/// links never replace an existing path, and fifo / char / block members are
/// written as regular files.
async fn extract_entry<R: AsyncRead + Unpin>(
    file: MemberFrame<'_, R>,
    layer_root: &Root,
    path: &Path,
    is_dir: bool,
    unpack_xattrs: bool,
    chunk: &mut Vec<u8>,
) -> UnpackResult<()> {
    let kind = file.header.kind;
    let link_target = matches!(kind, UstarKind::HardLink | UstarKind::SymbolicLink)
        .then(|| {
            file.effective_link_path()
                .map(|p| PathBuf::from(OsStr::from_bytes(p.as_ref())))
                .map_err(|source| UnpackError::ReadTarEntriesFailed {
                    source: io::Error::other(source),
                })
        })
        .transpose()?;
    let xattrs = match unpack_xattrs {
        true => collect_xattrs(&file.extensions),
        false => Vec::new(),
    };
    let mut payload = file.payload;

    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        layer_root
            .mkdir_all(parent, &Permissions::from_mode(CREATE_DIR_MODE))
            .map_err(|source| UnpackError::PathRsFailed { source })?;
    }

    let require_link_target = || {
        link_target
            .as_deref()
            .ok_or_else(|| UnpackError::UnpackFailed {
                source: io::Error::other("link listed but no link name found"),
            })
    };
    match kind {
        UstarKind::SymbolicLink => {
            let target = require_link_target()?;
            remove_existing(layer_root, path)?;
            layer_root
                .create(path, &InodeType::Symlink(target.to_path_buf()))
                .map_err(|source| UnpackError::PathRsFailed { source })
        }
        UstarKind::HardLink => {
            let target = resolve_hardlink_target(require_link_target()?).ok_or_else(|| {
                UnpackError::UnpackFailed {
                    source: io::Error::other("hardlink target resolves outside the layer root"),
                }
            })?;
            layer_root
                .create(path, &InodeType::Hardlink(target))
                .map_err(|source| UnpackError::PathRsFailed { source })
        }
        // GNU headers with a trailing '/' are directories too.
        _ if is_dir => {
            layer_root
                .mkdir_all(path, &Permissions::from_mode(CREATE_DIR_MODE))
                .map_err(|source| UnpackError::PathRsFailed { source })?;
            Ok(())
        }
        // Regular, contiguous, fifo, char and block members.
        _ => {
            remove_existing(layer_root, path)?;
            let file = layer_root
                .create_file(
                    path,
                    OpenFlags::O_WRONLY | OpenFlags::O_EXCL,
                    &Permissions::from_mode(CREATE_FILE_MODE),
                )
                .map_err(|source| UnpackError::PathRsFailed { source })?;
            let mut file = fs::File::from_std(file);
            while payload
                .next_chunk(chunk, PAYLOAD_CHUNK_BYTES)
                .await
                .map_err(|source| UnpackError::ReadTarEntriesFailed {
                    source: io::Error::other(source),
                })?
            {
                file.write_all(chunk)
                    .await
                    .map_err(|source| UnpackError::UnpackFailed { source })?;
            }
            file.flush()
                .await
                .map_err(|source| UnpackError::UnpackFailed { source })?;
            let file = file.into_std().await;
            for (key, value) in &xattrs {
                file.set_xattr(OsStr::from_bytes(key), value)
                    .map_err(|source| UnpackError::UnpackFailed { source })?;
            }
            Ok(())
        }
    }
}

/// Removes an existing non-directory at `path` so it can be recreated.
fn remove_existing(layer_root: &Root, path: &Path) -> UnpackResult<()> {
    match layer_root.resolve_nofollow(path) {
        Ok(_) => layer_root
            .remove_file(path)
            .map_err(|source| UnpackError::PathRsFailed { source }),
        Err(source)
            if matches!(
                source.kind(),
                pathrs::error::ErrorKind::OsError(Some(libc::ENOENT))
            ) =>
        {
            Ok(())
        }
        Err(source) => Err(UnpackError::PathRsFailed { source }),
    }
}

/// Sets atime and mtime of `path` inside the layer.
///
/// The parent is resolved by pathrs and the final component is not followed,
/// so symlinks in the layer cannot redirect the update outside of it.
fn set_times(layer_root: &Root, layer_dir: &Path, path: &Path, mtime: i64) -> UnpackResult<()> {
    let err_path = || layer_dir.join(path).display().to_string();
    let name = path
        .file_name()
        .ok_or_else(|| UnpackError::IllegalEntryName(err_path()))?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .map(|parent| layer_root.resolve(parent))
        .transpose()
        .map_err(|source| UnpackError::PathRsFailed { source })?;
    let dirfd = match &parent {
        Some(handle) => handle.as_fd(),
        None => layer_root.as_fd(),
    };

    let time = TimeSpec::new(mtime, 0);
    utimensat(dirfd, name, &time, &time, UtimensatFlags::NoFollowSymlink).map_err(|e| {
        UnpackError::SetMTimeFailed {
            source: e.into(),
            path: err_path(),
        }
    })
}

/// A pax record overrides the header field. A missing (all-NUL) header field
/// without a pax override is an error, as with tokio-tar.
fn owner_id(
    header: Option<u64>,
    extensions: &MemberExtensions<'_>,
    keyword: PaxKeyword,
    name: &str,
    err: impl Fn(anyhow::Error) -> UnpackError,
) -> UnpackResult<u32> {
    let id = match pax_numeric(extensions, &keyword) {
        Some(PaxValue::Value(value)) => *value,
        Some(PaxValue::Deleted) | None => {
            header.ok_or_else(|| err(anyhow!("corrupted {name} in header")))?
        }
    };
    id.try_into().map_err(|_| err(anyhow!("{name} too large")))
}

/// Link names are paths from the archive root.
///
/// Absolute names drop the leading `/` and keep `..` for pathrs, which clamps
/// at the layer root. Relative names are lexical from that same root; a `..`
/// that walks above the layer returns `None`.
fn resolve_hardlink_target(target: &Path) -> Option<PathBuf> {
    if target.is_absolute() {
        return Some(layer_relative_path(target));
    }

    let mut parts: Vec<Component<'_>> = Vec::new();
    for component in target.components() {
        match component {
            Component::CurDir | Component::Prefix(_) | Component::RootDir => {}
            Component::ParentDir => {
                parts.pop()?;
            }
            Component::Normal(_) => parts.push(component),
        }
    }
    Some(parts.iter().collect())
}

fn layer_relative_path(path: &Path) -> PathBuf {
    path.components()
        .filter(|c| {
            !matches!(
                c,
                Component::Prefix(_) | Component::RootDir | Component::CurDir
            )
        })
        .collect()
}

fn pax_numeric<'a>(
    extensions: &'a MemberExtensions<'_>,
    keyword: &PaxKeyword,
) -> Option<&'a PaxValue<u64>> {
    let MemberExtensions::Pax(state) = extensions else {
        return None;
    };
    match (keyword, state.effective_record(keyword)?) {
        (PaxKeyword::Uid, PaxRecord::Uid(v)) | (PaxKeyword::Gid, PaxRecord::Gid(v)) => Some(v),
        _ => None,
    }
}

fn collect_xattrs(extensions: &MemberExtensions<'_>) -> Vec<(Vec<u8>, Vec<u8>)> {
    let MemberExtensions::Pax(state) = extensions else {
        return Vec::new();
    };
    state
        .extensions()
        .flat_map(|ext| ext.records())
        .filter_map(|record| {
            let PaxRecord::Vendor {
                vendor,
                name,
                value: PaxValue::Value(bytes),
            } = record
            else {
                return None;
            };
            let key = (vendor.as_ref() == "SCHILY")
                .then(|| name.strip_prefix("xattr."))
                .flatten()?;
            Some((key.as_bytes().to_vec(), bytes.as_ref().to_vec()))
        })
        .collect()
}

fn dir_times(mtime: i64) -> [timeval; 2] {
    let atime = timeval {
        tv_sec: mtime,
        tv_usec: 0,
    };
    [atime, atime]
}

fn fchown_at(fd: BorrowedFd<'_>, uid: u32, gid: u32) -> Result<()> {
    let ret =
        unsafe { libc::fchownat(fd.as_raw_fd(), c"".as_ptr(), uid, gid, libc::AT_EMPTY_PATH) };
    if ret != 0 {
        bail!("failed to fchownat: {:?}", io::Error::last_os_error());
    }
    Ok(())
}

/// Set mode on the inode referenced by an `O_PATH` fd (`Root` / `Handle` from pathrs).
///
/// The underlying `fchmodat(2)` syscall has no flags argument, so `AT_EMPTY_PATH`
/// is only honored through the `fchmodat2(2)` syscall introduced in Linux 6.6.
/// On older guest kernels the libc falls back and rejects `AT_EMPTY_PATH` with
/// `EINVAL`. `chmod(2)` cannot be issued on an `O_PATH` fd directly either, so
/// resolve the inode via `/proc/self/fd/<N>`, which works on any kernel as long
/// as procfs is mounted (always the case in the guest).
fn fchmodat(fd: BorrowedFd<'_>, mode: u32) -> Result<()> {
    let proc_path = format!("/proc/self/fd/{}", fd.as_raw_fd());
    let proc_path =
        CString::new(proc_path).map_err(|_| anyhow!("procfs path contains null byte"))?;
    let ret = unsafe { libc::chmod(proc_path.as_ptr(), mode as libc::mode_t) };
    if ret != 0 {
        bail!("failed to chmod: {:?}", io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{FileTypeExt, MetadataExt, chown, lchown};
    use tokio::{
        fs::{self, File},
        io::{AsyncWriteExt, empty},
    };
    use tokio_tar::{Builder, EntryType, Header};

    use rstest::rstest;

    use super::*;

    #[tokio::test]
    #[cfg_attr(any(target_arch = "s390x", target_arch = "powerpc64"), ignore)]
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

    #[tokio::test]
    async fn test_unpack_tar_codec_pax() {
        use tar_codec::{ArchiveBuilder as _, EntryMetadata, TarEncoder};

        let mut encoded = Vec::new();
        {
            let mut encoder = TarEncoder::new(&mut encoded).builder();
            encoder
                .add_file("file.txt", b"hello".as_slice(), EntryMetadata::default())
                .await
                .unwrap();
            encoder.finish().await.unwrap();
        }

        let destination = tempfile::tempdir().unwrap().path().join("layer");
        unpack(encoded.as_slice(), &destination).await.unwrap();
        assert_eq!(
            fs::read(destination.join("file.txt")).await.unwrap(),
            b"hello"
        );
    }

    #[tokio::test]
    async fn test_unpack_layer_root_mtime() {
        let root_mtime = filetime::FileTime::from_unix_time(42_000, 0);
        let mut ar = Builder::new(Vec::new());
        let root_src = tempfile::tempdir().unwrap();
        let file_src = tempfile::tempdir().unwrap();

        filetime::set_file_mtime(root_src.path(), root_mtime).unwrap();
        ar.append_path_with_name(root_src.path(), ".")
            .await
            .unwrap();

        let file_path = file_src.path().join("file.txt");
        let mut f = File::create(&file_path).await.unwrap();
        f.write_all(b"data").await.unwrap();
        f.flush().await.unwrap();
        ar.append_file("file.txt", &mut File::open(&file_path).await.unwrap())
            .await
            .unwrap();

        let data = ar.into_inner().await.unwrap();
        let destination = tempfile::tempdir().unwrap().path().join("layer");
        unpack(data.as_slice(), &destination).await.unwrap();

        let metadata = fs::metadata(&destination).await.unwrap();
        let new_mtime = filetime::FileTime::from_last_modification_time(&metadata);
        assert_eq!(root_mtime, new_mtime);
    }

    fn header(kind: EntryType, path: &str, size: u64) -> Header {
        let mut hdr = Header::new_gnu();
        hdr.set_entry_type(kind);
        hdr.set_path(path).unwrap();
        hdr.set_size(size);
        hdr.set_mode(0o755);
        hdr.set_uid(0);
        hdr.set_gid(0);
        hdr.set_mtime(20_000);
        hdr
    }

    #[tokio::test]
    async fn test_unpack_metadata_stays_inside_layer() {
        let td = tempfile::tempdir().unwrap();
        let outside = td.path().join("outside");
        fs::create_dir(&outside).await.unwrap();
        let victim = outside.join("f");
        fs::write(&victim, b"host").await.unwrap();
        let victim_dir = outside.join("d");
        fs::create_dir(&victim_dir).await.unwrap();
        let victim_mtime = filetime::FileTime::from_unix_time(1_000_000, 0);
        filetime::set_file_mtime(&victim, victim_mtime).unwrap();
        filetime::set_file_mtime(&victim_dir, victim_mtime).unwrap();

        // `a` resolves to `layer/outside` through pathrs, but to `td/outside`
        // through the kernel.
        let mut ar = Builder::new(Vec::new());
        let mut hdr = header(EntryType::Directory, "outside/", 0);
        hdr.set_cksum();
        ar.append(&hdr, empty()).await.unwrap();
        let mut hdr = header(EntryType::Symlink, "a", 0);
        hdr.set_link_name("../outside").unwrap();
        hdr.set_cksum();
        ar.append(&hdr, empty()).await.unwrap();
        let mut hdr = header(EntryType::Directory, "a/d/", 0);
        hdr.set_cksum();
        ar.append(&hdr, empty()).await.unwrap();
        let mut hdr = header(EntryType::Regular, "a/f", 4);
        hdr.set_cksum();
        ar.append(&hdr, b"evil".as_slice()).await.unwrap();
        let data = ar.into_inner().await.unwrap();

        let destination = td.path().join("dest");
        unpack(data.as_slice(), &destination).await.unwrap();

        let mtime_of = |path: PathBuf| async move {
            filetime::FileTime::from_last_modification_time(&fs::metadata(path).await.unwrap())
        };
        assert_eq!(mtime_of(victim.clone()).await, victim_mtime);
        assert_eq!(fs::read(&victim).await.unwrap(), b"host");
        assert_eq!(mtime_of(victim_dir.clone()).await, victim_mtime);

        let unpacked = mtime_of(destination.join("outside/f")).await;
        assert_eq!(unpacked, filetime::FileTime::from_unix_time(20_000, 0));
        let unpacked_dir = mtime_of(destination.join("outside/d")).await;
        assert_eq!(unpacked_dir, filetime::FileTime::from_unix_time(20_000, 0));
    }

    #[tokio::test]
    async fn test_unpack_rejects_missing_uid() {
        let mut hdr = header(EntryType::Regular, "f", 0);
        hdr.as_old_mut().uid = [0; 8];
        hdr.set_cksum();
        let mut ar = Builder::new(Vec::new());
        ar.append(&hdr, empty()).await.unwrap();
        let data = ar.into_inner().await.unwrap();

        let destination = tempfile::tempdir().unwrap().path().join("layer");
        let res = unpack(data.as_slice(), &destination).await;
        assert!(
            matches!(res, Err(UnpackError::IllegalUid { .. })),
            "{res:?}"
        );
    }

    #[rstest]
    #[case::absolute_link_target("/etc/os-release", true)]
    #[case::relative_link_target("etc/os-release", true)]
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
