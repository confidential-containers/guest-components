// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use libc::timeval;
use std::collections::HashMap;
use std::ffi::{CString, NulError};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use tar::Archive;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum UnpackError {
    #[error("unpack destination already exists: {0}")]
    DestinationExists(PathBuf),

    #[error("failed to change symlink {0} timestamp: {1}")]
    SymlinkTimeStampError(String, #[source] io::Error),

    #[error("failed to directory {0} timestamp: {1}")]
    DirTimestampError(String, #[source] io::Error),

    #[error("failed to remove unpack destination directory: {0}")]
    UnpackDirRemoveFailed(std::io::Error),

    #[error("failed to create unpack destination directory: {0}")]
    UnpackCreateDirFail(std::io::Error),

    #[error("unpack failed to extract archive entry: {0}")]
    UnpackArchiveFail(std::io::Error),

    #[error("failed to get unpack archive member: {0}")]
    UnpackArchiveMemberGetFail(std::io::Error),

    #[error("failed to get archive file name: {0}")]
    UnpackArchiveMemberNameFail(std::io::Error),

    #[error("failed to unpack archive file {0} to {1}: {2}")]
    UnpackArchiveMemberFail(String, PathBuf, std::io::Error),

    #[error("failed to get modification time for file {0}: {1}")]
    GetModTimeFail(String, std::io::Error),

    #[error("failed to construct fill unpack path for {0}/{1}: {2}")]
    UnpackPathCreateFail(PathBuf, String, NulError),
}

type Result<T> = std::result::Result<T, UnpackError>;

/// Unpack the contents of tarball to the destination path
pub fn unpack<R: io::Read>(input: R, destination: &Path) -> Result<()> {
    let mut archive = Archive::new(input);

    if destination.exists() {
        return Err(UnpackError::DestinationExists(destination.to_path_buf()));
    }

    fs::create_dir_all(destination).map_err(|e| UnpackError::UnpackCreateDirFail(e))?;

    let mut dirs: HashMap<CString, [timeval; 2]> = HashMap::default();
    for file in archive
        .entries()
        .map_err(|e| UnpackError::UnpackArchiveFail(e))?
    {
        let mut file = file.map_err(|e| UnpackError::UnpackArchiveMemberGetFail(e))?;

        let filename = format!(
            "{}",
            file.path()
                .map_err(|e| UnpackError::UnpackArchiveMemberNameFail(e))?
                .display()
        );

        file.unpack_in(destination).map_err(|e| {
            UnpackError::UnpackArchiveMemberFail(filename.clone(), destination.to_path_buf(), e)
        })?;

        // tar-rs crate only preserve timestamps of files,
        // symlink file and directory are not covered.
        // upstream fix PR: https://github.com/alexcrichton/tar-rs/pull/217
        if file.header().entry_type().is_symlink() || file.header().entry_type().is_dir() {
            let mtime = file
                .header()
                .mtime()
                .map_err(|e| UnpackError::GetModTimeFail(filename.clone(), e))?
                as i64;

            let atime = timeval {
                tv_sec: mtime,
                tv_usec: 0,
            };
            let path = CString::new(format!("{}/{}", destination.display(), filename.clone()))
                .map_err(|e| {
                    UnpackError::UnpackPathCreateFail(
                        destination.to_path_buf(),
                        filename.clone(),
                        e,
                    )
                })?;

            let times = [atime, atime];

            if file.header().entry_type().is_dir() {
                dirs.insert(path, times);
            } else {
                let ret = unsafe { libc::lutimes(path.as_ptr(), times.as_ptr()) };

                if ret != 0 {
                    return Err(UnpackError::SymlinkTimeStampError(
                        format!("{}", path.to_string_lossy()),
                        io::Error::last_os_error(),
                    ));
                }
            }
        }
    }

    // Directory timestamps need update after all files are extracted.
    for (k, v) in dirs.iter() {
        let ret = unsafe { libc::utimes(k.as_ptr(), v.as_ptr()) };
        if ret != 0 {
            return Err(UnpackError::DirTimestampError(
                format!("{}", k.to_string_lossy()),
                io::Error::last_os_error(),
            ));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use filetime;
    use std::fs::File;
    use std::io::prelude::*;
    use tempfile;

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

        let path = tempdir.path().join("dir");
        fs::create_dir(&path).unwrap();

        filetime::set_file_mtime(&path, mtime).unwrap();
        ar.append_path_with_name(&path, "dir").unwrap();

        // TODO: Add more file types like symlink, char, block devices.
        let data = ar.into_inner().unwrap();
        tempdir.close().unwrap();

        let destination = Path::new("/tmp/image_test_dir");
        if destination.exists() {
            fs::remove_dir_all(destination).unwrap();
        }

        assert!(unpack(data.as_slice(), destination).is_ok());

        let path = destination.join("file.txt");
        let metadata = fs::metadata(&path).unwrap();
        let new_mtime = filetime::FileTime::from_last_modification_time(&metadata);
        assert_eq!(mtime, new_mtime);

        let path = destination.join("dir");
        let metadata = fs::metadata(&path).unwrap();
        let new_mtime = filetime::FileTime::from_last_modification_time(&metadata);
        assert_eq!(mtime, new_mtime);

        // destination already exists
        assert!(unpack(data.as_slice(), destination).is_err());
    }
}
