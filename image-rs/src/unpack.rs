// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::{bail, Context, Result};
use filetime::FileTime;
use futures::StreamExt;
use libc::timeval;
use log::warn;
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

/// Unpack the contents of tarball to the destination path
pub async fn unpack<R: AsyncRead + Unpin>(input: R, destination: &Path) -> Result<()> {
    let mut archive = ArchiveBuilder::new(input)
        .set_ignore_zeros(true)
        .set_unpack_xattrs(true)
        .set_preserve_permissions(true)
        .build();
    let mut entries = archive
        .entries()
        .context("failed to read entries from the tar")?;

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

    let mut dirs: HashMap<CString, [timeval; 2]> = HashMap::default();
    while let Some(file) = entries.next().await {
        let mut file = file?;

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

        file.unpack_in(destination).await?;

        let path = CString::new(format!(
            "{}/{}",
            destination.display(),
            file.path()?.display()
        ))?;

        let file_path = path.to_str().expect("must be utf8");

        let kind = file.header().entry_type();
        let mode = file.header().mode().ok();
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
        let ret = unsafe { libc::utimes(k.as_ptr(), v.as_ptr()) };
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
            let ret = unsafe { libc::fchown(f.as_fd().as_raw_fd(), uid, gid) };
            if ret != 0 {
                bail!(
                    "failed to set ownerships of file: {:?} chown error: {:?}",
                    dst,
                    io::Error::last_os_error()
                );
            }
        }
        ChownType::LChown => {
            let ret = unsafe { libc::lchown(dst.as_ptr(), uid, gid) };
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

        let path = tempdir.path().join("dir");
        fs::create_dir(&path).await.unwrap();

        filetime::set_file_mtime(&path, mtime).unwrap();
        ar.append_path_with_name(&path, "dir").await.unwrap();

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

        let path = destination.join("dir");
        let metadata = fs::metadata(path).await.unwrap();
        let new_mtime = filetime::FileTime::from_last_modification_time(&metadata);
        assert_eq!(mtime, new_mtime);

        // though destination already exists, it will be deleted
        // and rewrite
        assert!(unpack(data.as_slice(), destination).await.is_ok());
    }
}
