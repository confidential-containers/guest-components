// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::anyhow;
use anyhow::Context;
use anyhow::{bail, Result};
use libc::timeval;
use log::warn;
use std::collections::HashMap;
use std::convert::TryInto;
use std::ffi::CString;
use std::fs;
use std::io;
use std::path::Path;
use tar::Archive;
use tar::Header;

// See https://github.com/opencontainers/image-spec/blob/main/layer.md#whiteouts
const WHITEOUT_PREFIX: &str = ".wh.";
const WHITEOUT_OPAQUE_DIR: &str = ".wh..wh..opq";

/// Unpack the contents of tarball to the destination path
pub fn unpack<R: io::Read>(input: R, destination: &Path) -> Result<()> {
    let mut archive = Archive::new(input);
    archive.set_preserve_ownerships(true);
    archive.set_preserve_permissions(true);

    if destination.exists() {
        warn!(
            "unpack destination {:?} already exists, will delete and rerwrite the layer",
            destination
        );
        fs::remove_dir_all(destination)
            .context("Failed to delete existed broken layer when unpacking")?;
    }

    fs::create_dir_all(destination)?;

    let mut dirs: HashMap<CString, [timeval; 2]> = HashMap::default();
    for file in archive.entries()? {
        let mut file = file?;

        if !convert_whiteout(&file.path()?, file.header(), destination)? {
            continue;
        }

        file.unpack_in(destination)?;

        // tar-rs crate only preserve timestamps of files,
        // symlink file and directory are not covered.
        // upstream fix PR: https://github.com/alexcrichton/tar-rs/pull/217
        if file.header().entry_type().is_symlink() || file.header().entry_type().is_dir() {
            let mtime = file.header().mtime()? as i64;

            let atime = timeval {
                tv_sec: mtime,
                tv_usec: 0,
            };
            let path = CString::new(format!(
                "{}/{}",
                destination.display(),
                file.path()?.display()
            ))?;

            let times = [atime, atime];

            if file.header().entry_type().is_dir() {
                dirs.insert(path, times);
            } else {
                let ret = unsafe { libc::lutimes(path.as_ptr(), times.as_ptr()) };
                if ret != 0 {
                    bail!(
                        "change symlink file: {:?} utime error: {:?}",
                        path,
                        io::Error::last_os_error()
                    );
                }
            }
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

fn convert_whiteout(path: &Path, header: &Header, destination: &Path) -> Result<bool> {
    // Handle whiteout conversion
    let name = path
        .file_name()
        .unwrap_or_default()
        .to_str()
        .ok_or(anyhow!("Invalid unicode in whiteout path: {:?}", path))?;

    if name.starts_with(WHITEOUT_PREFIX) {
        let parent = path
            .parent()
            .ok_or(anyhow!("Invalid whiteout parent for path: {:?}", path))?;

        if name == WHITEOUT_OPAQUE_DIR {
            let destination_parent = destination.join(parent);
            xattr::set(destination_parent, "trusted.overlay.opaque", b"y")?;
            return Ok(false);
        }

        let original_name = name
            .strip_prefix(WHITEOUT_PREFIX)
            .ok_or(anyhow!("Failed to strip whiteout prefix for: {}", name))?;
        let original_path = parent.join(original_name);
        let path = CString::new(format!(
            "{}/{}",
            destination.display(),
            original_path.display()
        ))?;

        let ret = unsafe { libc::mknod(path.as_ptr(), libc::S_IFCHR, 0) };
        if ret != 0 {
            bail!("mknod: {:?} error: {:?}", path, io::Error::last_os_error());
        }

        let uid: libc::uid_t = header
            .uid()?
            .try_into()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "UID is too large!"))?;
        let gid: libc::gid_t = header
            .gid()?
            .try_into()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "GID is too large!"))?;

        let ret = unsafe { libc::lchown(path.as_ptr(), uid, gid) };
        if ret != 0 {
            bail!(
                "change ownership: {:?} error: {:?}",
                path,
                io::Error::last_os_error()
            );
        }
        return Ok(false);
    }

    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::prelude::*;
    use std::os::unix::fs::FileTypeExt;

    #[test]
    fn test_unpack() {
        let mut ar = tar::Builder::new(Vec::new());
        let tempdir = tempfile::tempdir().unwrap();

        let path = tempdir.path().join("file.txt");
        File::create(&path)
            .unwrap()
            .write_all(b"file data")
            .unwrap();

        let mtime = filetime::FileTime::from_unix_time(20_000, 0);
        filetime::set_file_mtime(&path, mtime).unwrap();
        ar.append_file("file.txt", &mut File::open(&path).unwrap())
            .unwrap();

        let path = tempdir
            .path()
            .join(WHITEOUT_PREFIX.to_owned() + "whiteout_file.txt");
        File::create(&path).unwrap();
        ar.append_file(
            WHITEOUT_PREFIX.to_owned() + "whiteout_file.txt",
            &mut File::open(&path).unwrap(),
        )
        .unwrap();

        let path = tempdir.path().join("dir");
        fs::create_dir(&path).unwrap();

        filetime::set_file_mtime(&path, mtime).unwrap();
        ar.append_path_with_name(&path, "dir").unwrap();

        let path = tempdir.path().join("whiteout_dir");
        fs::create_dir(&path).unwrap();
        ar.append_path_with_name(&path, "whiteout_dir").unwrap();

        let path = tempdir
            .path()
            .join("whiteout_dir/".to_owned() + WHITEOUT_OPAQUE_DIR);
        fs::create_dir(&path).unwrap();
        ar.append_path_with_name(&path, "whiteout_dir/".to_owned() + WHITEOUT_OPAQUE_DIR)
            .unwrap();

        // TODO: Add more file types like symlink, char, block devices.
        let data = ar.into_inner().unwrap();
        tempdir.close().unwrap();

        let destination = Path::new("/tmp/image_test_dir");
        if destination.exists() {
            fs::remove_dir_all(destination).unwrap();
        }

        assert!(unpack(data.as_slice(), destination).is_ok());

        let path = destination.join("file.txt");
        let metadata = fs::metadata(path).unwrap();
        let new_mtime = filetime::FileTime::from_last_modification_time(&metadata);
        assert_eq!(mtime, new_mtime);

        let path = destination.join("whiteout_file.txt");
        let metadata = fs::metadata(path).unwrap();
        assert!(metadata.file_type().is_char_device());

        let path = destination.join("dir");
        let metadata = fs::metadata(path).unwrap();
        let new_mtime = filetime::FileTime::from_last_modification_time(&metadata);
        assert_eq!(mtime, new_mtime);

        let path = destination.join("whiteout_dir");
        let opaque = xattr::get(path, "trusted.overlay.opaque").unwrap().unwrap();
        assert_eq!(opaque, b"y");

        // though destination already exists, it will be deleted
        // and rewrite
        assert!(unpack(data.as_slice(), destination).is_ok());
    }
}
