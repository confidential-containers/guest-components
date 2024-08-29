// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, bail, Context, Result};
use filetime::FileTime;
use futures::StreamExt;
use log::{debug, warn};
use nix::libc::timeval;
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
    path::Path,
};
use tokio::{fs, io::AsyncRead};
use tokio_tar::ArchiveBuilder;
use xattr::FileExt;

// TODO: Add unit tests for both xattr supporting case and
// non-supporting case.
fn is_attr_available(path: &Path) -> Result<bool> {
    let dest = std::fs::File::open(path)?;
    match dest.set_xattr("user.overlay.origin", b"") {
        Ok(_) => {
            debug!("xattrs supported for {path:?}");
            Ok(true)
        }
        Err(e) => {
            debug!("xattrs is not supported for {path:?}, because {e}");
            Ok(false)
        }
    }
}

const WHITEOUT_PREFIX: &str = ".wh.";
const WHITEOUT_OPAQUE_DIR: &str = ".wh..wh..opq";

/// Returns whether the file name is a whiteout file
fn is_whiteout(name: &str) -> bool {
    name.starts_with(WHITEOUT_PREFIX)
}

/// Converts a whiteout file or opaque directory. See OverlayFS and Aufs documentation for details
/// https://www.kernel.org/doc/Documentation/filesystems/overlayfs.txt
/// https://aufs.sourceforge.net/aufs.html
async fn convert_whiteout(
    name: &str,
    path: &Path,
    uid: u32,
    gid: u32,
    mode: Option<u32>,
    destination: &Path,
) -> Result<()> {
    let parent = path
        .parent()
        .ok_or(anyhow!("Invalid whiteout parent for path: {:?}", path))?;

    // Handle opaque directories
    if name == WHITEOUT_OPAQUE_DIR {
        let destination_parent = destination.join(parent);
        xattr::set(destination_parent, "trusted.overlay.opaque", b"y")?;
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

    let ret = unsafe { nix::libc::mknod(path.as_ptr(), nix::libc::S_IFCHR, 0) };
    if ret != 0 {
        bail!("mknod: {:?} error: {:?}", path, io::Error::last_os_error());
    }

    set_perms_ownerships(&path, ChownType::LChown, uid, gid, mode).await
}

/// Unpack the contents of tarball to the destination path
pub async fn unpack<R: AsyncRead + Unpin>(input: R, destination: &Path) -> Result<()> {
    if destination.exists() {
        warn!(
            "unpack destination {:?} already exists, will delete and rerwrite the layer",
            destination
        );
        fs::remove_dir_all(destination)
            .await
            .context("Failed to delete existed broken layer when unpacking")?;
    }

    fs::create_dir_all(destination).await?;

    let attr_available = is_attr_available(destination)?;
    let mut archive = ArchiveBuilder::new(input)
        .set_ignore_zeros(true)
        .set_unpack_xattrs(attr_available)
        .set_preserve_permissions(true)
        .build();

    let mut entries = archive
        .entries()
        .context("failed to read entries from the tar")?;

    let mut dirs: HashMap<CString, [timeval; 2]> = HashMap::default();
    while let Some(file) = entries.next().await {
        let mut file = file?;

        let entry_path = file.path()?;
        let entry_name = entry_path
            .file_name()
            .unwrap_or_default()
            .to_str()
            .ok_or(anyhow!("Invalid unicode in path: {:?}", entry_path))?;
        let uid = file
            .header()
            .uid()?
            .try_into()
            .context("UID is too large!")?;
        let gid = file
            .header()
            .gid()?
            .try_into()
            .context("GID is too large!")?;
        let mode = file.header().mode().ok();

        if attr_available && is_whiteout(entry_name) {
            convert_whiteout(entry_name, &entry_path, uid, gid, mode, destination).await?;
            continue;
        }

        file.unpack_in(destination).await?;

        let path = CString::new(format!(
            "{}/{}",
            destination.display(),
            file.path()?.display()
        ))?;

        let file_path = path.to_str().expect("must be utf8");

        let kind = file.header().entry_type();
        let mtime = file.header().mtime()? as i64;

        // krata-tokio-tar crate does not provide a way to preserve permissions
        // for all kinds of files.
        //
        // this crate also does not cover symlink files/dir mtime.
        //
        // because we changed the files ownership manually, thus we need to reset
        // the mtime again.
        if kind.is_dir() || file.header().as_ustar().is_none() && file.path_bytes().ends_with(b"/")
        {
            set_perms_ownerships(&path, ChownType::LChown, uid, gid, mode).await?;
            let atime = timeval {
                tv_sec: mtime,
                tv_usec: 0,
            };

            let times = [atime, atime];

            dirs.insert(path.clone(), times);
        } else if kind.is_symlink() {
            let mtime = FileTime::from_unix_time(mtime, 0);
            filetime::set_symlink_file_times(file_path, mtime, mtime)
                .context(format!("failed to set mtime for sym link `{file_path}`"))?;
        } else if !kind.is_hard_link() {
            // for other files except link we use fchown
            let f = fs::OpenOptions::new()
                .write(true)
                .open(file_path)
                .await
                .context("open file failed")?;

            set_perms_ownerships(&path, ChownType::FChown(f), uid, gid, mode).await?;

            // set mtime
            let mtime = FileTime::from_unix_time(mtime, 0);
            filetime::set_file_times(file_path, mtime, mtime)
                .context(format!("failed to set mtime for `{file_path}`"))?;
        }
    }

    // Directory timestamps need update after all files are extracted.
    for (k, v) in dirs.iter() {
        let ret = unsafe { nix::libc::utimes(k.as_ptr(), v.as_ptr()) };
        if ret != 0 {
            bail!(
                "change directory: {:?} utime error: {:?}",
                k,
                io::Error::last_os_error()
            );
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
    match chown {
        ChownType::FChown(f) => {
            let ret = unsafe { nix::libc::fchown(f.as_fd().as_raw_fd(), uid, gid) };
            if ret != 0 {
                bail!(
                    "failed to set ownerships of file: {:?} chown error: {:?}",
                    dst,
                    io::Error::last_os_error()
                );
            }
        }
        ChownType::LChown => {
            let ret = unsafe { nix::libc::lchown(dst.as_ptr(), uid, gid) };
            if ret != 0 {
                bail!(
                    "failed to set ownerships of file: {:?} lchown error: {:?}",
                    dst,
                    io::Error::last_os_error()
                );
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

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{chown, lchown, MetadataExt};

    use std::os::unix::fs::FileTypeExt;
    use tokio::{
        fs::{self, File},
        io::AsyncWriteExt,
    };
    use tokio_tar::Builder;

    use super::*;

    #[tokio::test]
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

        let attr_available = is_attr_available(destination).unwrap();
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

        // though destination already exists, it will be deleted
        // and rewrite
        assert!(unpack(data.as_slice(), destination).await.is_ok());
    }
}
