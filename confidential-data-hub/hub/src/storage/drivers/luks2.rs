// Copyright (c) 2024 Intel
// Copyright (c) 2025 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! # LUKS2
//!
//! This module uses the `cryptsetup` binary to encrypt/decrypt a block device with LUKS2.
//!
//! It requires the `cryptsetup` and `blkid` CLIs to be installed (e.g. `cryptsetup-bin` and
//! `util-linux` on Debian/Ubuntu).
//! No libcryptsetup-rs is linked, so the hub binary can be built as fully static.

use std::{
    collections::HashMap,
    fs::{File, OpenOptions},
    io::SeekFrom,
    os::unix::fs::FileExt,
    os::unix::fs::{FileTypeExt, MetadataExt},
    path::Path,
    sync::{Arc, LazyLock, Weak},
    time::Instant,
};

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as b64, Engine};
use const_format::concatcp;
use hmac::{Hmac, KeyInit, Mac};
use nix::mount::{mount, MsFlags};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;
use tokio::{
    fs::symlink,
    io::{AsyncReadExt, AsyncSeekExt},
    sync::Mutex,
};
use tracing::{debug, info, warn};
use zeroize::Zeroizing;

use crate::hub::CDH_BASE_DIR;
use crate::storage::drivers::filesystem::{FsFormatter, FsType};
use crate::storage::drivers::{run_command, run_command_output};
use crate::storage::volume_type::blockdevice::SourceType;

/// Algorithm of the integrity hash (dm-integrity format name)
const HMAC_SHA256: &str = "hmac-sha256";
const HMAC_SHA256_STATUS: &str = "hmac(sha256)";

const SECTOR_SIZE: u32 = 4096;

const CRYPTSETUP_BIN: &str = "cryptsetup";
const BLKID_BIN: &str = "blkid";

pub const LUKS_HEADERS_STORAGE_DIR: &str = concatcp!(CDH_BASE_DIR, "/luks-headers");
pub const LUKS_HEADER_FILE_SUFFIX: &str = ".header";
pub const LUKS2_HEADER_MIN_SIZE_BYTES: u64 = 16 * 1024 * 1024;

const PERSISTENT_VOLUME_ID_MAX_BYTES: usize = 256;
const PERSISTENT_KEY_MIN_BYTES: usize = 32;
const PERSISTENT_KEY_MAX_BYTES: usize = 4096;
const PERSISTENT_MAPPER_PREFIX: &str = "coco-pv-";
const ZERO_SCAN_BUFFER_SIZE: usize = 16 * 1024 * 1024;
const ZERO_SCAN_PROGRESS_INTERVAL_BYTES: u64 = 64 * 1024 * 1024 * 1024;

// The header MAC cannot live in the header it authenticates or in data that is
// unavailable before the mapper opens. Fix the LUKS2 header at 16 MiB and move
// the payload by 8 KiB, leaving room for two crash-tolerant state records.
const PERSISTENT_METADATA_MAGIC: &[u8; 8] = b"COCOPV\0\0";
const PERSISTENT_METADATA_VERSION: u16 = 1;
const PERSISTENT_METADATA_SLOT_BYTES: usize = 4096;
const PERSISTENT_METADATA_SLOT_COUNT: usize = 2;
const PERSISTENT_HEADER_BYTES: usize = LUKS2_HEADER_MIN_SIZE_BYTES as usize;
const PERSISTENT_LUKS2_METADATA_AREA_BYTES: u64 = 16 * 1024;
const PERSISTENT_LUKS2_KEYSLOTS_AREA_BYTES: u64 =
    LUKS2_HEADER_MIN_SIZE_BYTES - (2 * PERSISTENT_LUKS2_METADATA_AREA_BYTES);
const PERSISTENT_METADATA_OFFSET_BYTES: u64 = LUKS2_HEADER_MIN_SIZE_BYTES;
const PERSISTENT_DATA_OFFSET_BYTES: u64 = PERSISTENT_METADATA_OFFSET_BYTES
    + (PERSISTENT_METADATA_SLOT_BYTES * PERSISTENT_METADATA_SLOT_COUNT) as u64;
const PERSISTENT_DATA_OFFSET_SECTORS: u64 = PERSISTENT_DATA_OFFSET_BYTES / 512;
const PERSISTENT_RECORD_MAC_OFFSET: usize = 84;
const PERSISTENT_RECORD_MAC_BYTES: usize = 32;
const PERSISTENT_HEADER_MAC_DOMAIN: &[u8] = b"coco-cdh-persistent-luks2-header-v1";
const PERSISTENT_RECORD_MAC_DOMAIN: &[u8] = b"coco-cdh-persistent-luks2-record-v1";
const PERSISTENT_AUTH_KEY_DOMAIN: &[u8] = b"coco-cdh-persistent-luks2-auth-key-v1";

type HmacSha256 = Hmac<Sha256>;

/// A stable tenant-provided identity for a persistent encrypted volume.
///
/// The raw value never becomes a path or device-mapper name. A digest is used
/// for both, which keeps transient guest device paths out of persistent state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PersistentVolumeId(String);

impl TryFrom<&str> for PersistentVolumeId {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self> {
        if value.is_empty()
            || value.len() > PERSISTENT_VOLUME_ID_MAX_BYTES
            || !value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric()
                    || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/' | b'@')
            })
            || value
                .split('/')
                .any(|component| matches!(component, "" | "." | ".."))
        {
            bail!("persistent volume ID must be bounded canonical ASCII")
        }
        Ok(Self(value.to_string()))
    }
}

impl PersistentVolumeId {
    fn digest(&self) -> [u8; 32] {
        Sha256::digest(self.0.as_bytes()).into()
    }

    pub(crate) fn mapper_name(&self) -> String {
        format!("{PERSISTENT_MAPPER_PREFIX}{}", b64.encode(self.digest()))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum FilesystemProbe {
    Unformatted,
    Filesystem(String),
    Indeterminate,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PersistentFilesystemAction {
    FormatThenMount,
    MountExisting,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PersistentLuksState {
    Prepared,
    Initializing,
    Ready,
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
struct DeviceNumber {
    major: u64,
    minor: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PersistentMetadataRecord {
    state: PersistentLuksState,
    sequence: u64,
    volume_id_digest: [u8; 32],
    header_mac: [u8; 32],
}

impl PersistentMetadataRecord {
    fn prepared(volume_id: &PersistentVolumeId) -> Self {
        Self {
            state: PersistentLuksState::Prepared,
            sequence: 1,
            volume_id_digest: volume_id.digest(),
            header_mac: [0; 32],
        }
    }

    fn encode(&self, auth_key: &[u8]) -> Result<[u8; PERSISTENT_METADATA_SLOT_BYTES]> {
        let mut bytes = [0u8; PERSISTENT_METADATA_SLOT_BYTES];
        bytes[..8].copy_from_slice(PERSISTENT_METADATA_MAGIC);
        bytes[8..10].copy_from_slice(&PERSISTENT_METADATA_VERSION.to_be_bytes());
        bytes[10] = match self.state {
            PersistentLuksState::Prepared => 1,
            PersistentLuksState::Initializing => 2,
            PersistentLuksState::Ready => 3,
        };
        bytes[12..20].copy_from_slice(&self.sequence.to_be_bytes());
        bytes[20..52].copy_from_slice(&self.volume_id_digest);
        bytes[52..84].copy_from_slice(&self.header_mac);

        let mac = compute_hmac(auth_key, PERSISTENT_RECORD_MAC_DOMAIN, &[&bytes])?;
        bytes[PERSISTENT_RECORD_MAC_OFFSET
            ..PERSISTENT_RECORD_MAC_OFFSET + PERSISTENT_RECORD_MAC_BYTES]
            .copy_from_slice(&mac);
        Ok(bytes)
    }

    fn decode(
        mut bytes: [u8; PERSISTENT_METADATA_SLOT_BYTES],
        auth_key: &[u8],
        volume_id: &PersistentVolumeId,
    ) -> Result<Option<Self>> {
        if bytes.iter().all(|byte| *byte == 0) {
            return Ok(None);
        }
        if &bytes[..8] != PERSISTENT_METADATA_MAGIC {
            bail!("persistent LUKS2 metadata has an invalid magic value")
        }
        if u16::from_be_bytes(bytes[8..10].try_into().unwrap()) != PERSISTENT_METADATA_VERSION {
            bail!("persistent LUKS2 metadata version is not supported")
        }
        if bytes[11] != 0
            || bytes[PERSISTENT_RECORD_MAC_OFFSET + PERSISTENT_RECORD_MAC_BYTES..]
                .iter()
                .any(|byte| *byte != 0)
        {
            bail!("persistent LUKS2 metadata has nonzero reserved fields")
        }

        let expected_mac: [u8; 32] = bytes[PERSISTENT_RECORD_MAC_OFFSET
            ..PERSISTENT_RECORD_MAC_OFFSET + PERSISTENT_RECORD_MAC_BYTES]
            .try_into()
            .unwrap();
        bytes[PERSISTENT_RECORD_MAC_OFFSET
            ..PERSISTENT_RECORD_MAC_OFFSET + PERSISTENT_RECORD_MAC_BYTES]
            .fill(0);
        verify_hmac(
            auth_key,
            PERSISTENT_RECORD_MAC_DOMAIN,
            &[&bytes],
            &expected_mac,
        )
        .context("authenticate persistent LUKS2 metadata")?;

        let volume_id_digest = bytes[20..52].try_into().unwrap();
        if volume_id_digest != volume_id.digest() {
            bail!("persistent LUKS2 metadata belongs to another volume")
        }
        let state = match bytes[10] {
            1 => PersistentLuksState::Prepared,
            2 => PersistentLuksState::Initializing,
            3 => PersistentLuksState::Ready,
            _ => bail!("persistent LUKS2 metadata has an invalid state"),
        };
        let sequence = u64::from_be_bytes(bytes[12..20].try_into().unwrap());
        if !matches!(
            (state, sequence),
            (PersistentLuksState::Prepared, 1)
                | (PersistentLuksState::Initializing, 2)
                | (PersistentLuksState::Ready, 3)
        ) {
            bail!("persistent LUKS2 metadata state and sequence do not match")
        }
        let header_mac = bytes[52..84].try_into().unwrap();
        if state == PersistentLuksState::Prepared && header_mac != [0; 32] {
            bail!("prepared persistent LUKS2 metadata contains a header MAC")
        }
        if state != PersistentLuksState::Prepared && header_mac == [0; 32] {
            bail!("persistent LUKS2 metadata is missing its header MAC")
        }

        Ok(Some(Self {
            state,
            sequence,
            volume_id_digest,
            header_mac,
        }))
    }

    fn with_header(&self, header_mac: [u8; 32]) -> Result<Self> {
        if self.state != PersistentLuksState::Prepared {
            bail!("persistent LUKS2 header is already committed")
        }
        Ok(Self {
            state: PersistentLuksState::Initializing,
            sequence: self
                .sequence
                .checked_add(1)
                .context("persistent LUKS2 metadata sequence overflow")?,
            volume_id_digest: self.volume_id_digest,
            header_mac,
        })
    }

    fn ready(&self) -> Result<Self> {
        if self.state != PersistentLuksState::Initializing {
            bail!("persistent LUKS2 metadata is not initializing")
        }
        Ok(Self {
            state: PersistentLuksState::Ready,
            sequence: self
                .sequence
                .checked_add(1)
                .context("persistent LUKS2 metadata sequence overflow")?,
            volume_id_digest: self.volume_id_digest,
            header_mac: self.header_mac,
        })
    }
}

fn derive_persistent_auth_key(
    key: &[u8],
    volume_id: &PersistentVolumeId,
) -> Result<Zeroizing<Vec<u8>>> {
    Ok(Zeroizing::new(
        compute_hmac(key, PERSISTENT_AUTH_KEY_DOMAIN, &[&volume_id.digest()])?.to_vec(),
    ))
}

fn validate_persistent_key(key: &[u8]) -> Result<()> {
    if !(PERSISTENT_KEY_MIN_BYTES..=PERSISTENT_KEY_MAX_BYTES).contains(&key.len()) {
        bail!("persistent LUKS2 keys must contain between 32 and 4096 bytes")
    }
    Ok(())
}

fn compute_hmac(key: &[u8], domain: &[u8], parts: &[&[u8]]) -> Result<[u8; 32]> {
    let mut mac = HmacSha256::new_from_slice(key).context("initialize HMAC-SHA256")?;
    mac.update(domain);
    for part in parts {
        mac.update(part);
    }
    Ok(mac.finalize().into_bytes().into())
}

fn verify_hmac(key: &[u8], domain: &[u8], parts: &[&[u8]], expected: &[u8]) -> Result<()> {
    let mut mac = HmacSha256::new_from_slice(key).context("initialize HMAC-SHA256")?;
    mac.update(domain);
    for part in parts {
        mac.update(part);
    }
    mac.verify_slice(expected)
        .map_err(|_| anyhow::anyhow!("HMAC-SHA256 mismatch"))
}

/// Device paths are aliases, so locking by path would allow two requests to
/// race between the zero scan and format. Major/minor identity closes that
/// race without serializing unrelated volumes.
#[derive(Default)]
struct PersistentMountLocks {
    locks: Mutex<HashMap<DeviceNumber, Weak<Mutex<()>>>>,
}

impl PersistentMountLocks {
    async fn for_device(&self, device: DeviceNumber) -> Arc<Mutex<()>> {
        let mut locks = self.locks.lock().await;
        locks.retain(|_, lock| lock.strong_count() != 0);
        if let Some(lock) = locks.get(&device).and_then(Weak::upgrade) {
            return lock;
        }

        let lock = Arc::new(Mutex::new(()));
        locks.insert(device, Arc::downgrade(&lock));
        lock
    }
}

static PERSISTENT_MOUNT_LOCKS: LazyLock<PersistentMountLocks> =
    LazyLock::new(PersistentMountLocks::default);

#[derive(Debug, PartialEq, Eq)]
struct MountedFilesystem {
    device: DeviceNumber,
    filesystem_type: String,
}

/// Returns the path where the detached LUKS header for the given device is stored.
pub fn luks_header_path(device_path: &str) -> String {
    let name = b64.encode(device_path.as_bytes());
    format!(
        "{}/{}{}",
        LUKS_HEADERS_STORAGE_DIR, name, LUKS_HEADER_FILE_SUFFIX
    )
}

/// Creates and sizes the LUKS header file at `header_path`.
pub fn prepare_luks_header_file(header_path: &str) -> std::io::Result<()> {
    if let Some(parent) = Path::new(header_path).parent() {
        std::fs::create_dir_all(parent)?;
    }
    let file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(header_path)?;
    file.set_len(LUKS2_HEADER_MIN_SIZE_BYTES)?;
    Ok(())
}

/// The type of the target mount point.
#[derive(Serialize, Deserialize, PartialEq, Debug, Eq)]
#[serde(tag = "targetType")]
#[serde(rename_all = "camelCase")]
pub enum TargetType {
    /// The target is a device.
    Device,

    /// The target is a filesystem directory.
    FileSystem {
        /// The type of the target filesystem.
        /// In some cases, the filesystem type is determined by the higher
        /// level encryption_type ([`BlockDeviceEncryptType`]), so this
        /// field will be optional.
        #[serde(rename = "filesystemType")]
        #[serde(default)]
        filesystem_type: FsType,

        /// Extra options passed verbatim to mkfs.<fs> when it is needed.
        ///
        /// For LUKS2 + dm-integrity + ext4 on an empty device, CDH adds
        /// integrity-compatible ext4 defaults when the caller has not provided
        /// an explicit setting. In particular, CDH defaults lazy_itable_init to
        /// 0 to avoid lazy inode table writes against no-wipe dm-integrity
        /// devices.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[serde(rename = "mkfsOpts")]
        mkfs_opts: Option<String>,
    },
}

#[derive(Default)]
pub struct Luks2Formatter {
    pub integrity: bool,
}

#[derive(Clone, Copy)]
enum IntegrityInitialization {
    SkipWipeWithoutJournal,
    CompleteWithJournal,
}

impl Luks2Formatter {
    pub fn with_integrity(mut self, integrity: bool) -> Self {
        self.integrity = integrity;
        self
    }

    /// Encrypt (format) a block device as LUKS2 using the `cryptsetup` binary.
    pub fn encrypt_device(
        &self,
        device_path: &str,
        header_path: Option<&str>,
        passphrase: &[u8],
    ) -> anyhow::Result<()> {
        self.encrypt_device_with_payload_alignment(
            device_path,
            header_path,
            None,
            IntegrityInitialization::SkipWipeWithoutJournal,
            passphrase,
        )
    }

    fn encrypt_device_with_payload_alignment(
        &self,
        device_path: &str,
        header_path: Option<&str>,
        payload_alignment_sectors: Option<u64>,
        integrity_initialization: IntegrityInitialization,
        passphrase: &[u8],
    ) -> anyhow::Result<()> {
        let sector_size_str = SECTOR_SIZE.to_string();
        let payload_alignment_str =
            payload_alignment_sectors.map(|alignment| alignment.to_string());
        let metadata_area_size = PERSISTENT_LUKS2_METADATA_AREA_BYTES.to_string();
        let keyslots_area_size = PERSISTENT_LUKS2_KEYSLOTS_AREA_BYTES.to_string();

        let mut args: Vec<&str> = vec![
            "--batch-mode",
            "luksFormat",
            "--type",
            "luks2",
            "--cipher",
            "aes-xts-plain64",
            "--sector-size",
            &sector_size_str,
        ];

        if let Some(h) = header_path {
            args.push("--header");
            args.push(h);
        }

        if let Some(alignment) = payload_alignment_str.as_deref() {
            args.push("--align-payload");
            args.push(alignment);
            args.push("--luks2-metadata-size");
            args.push(&metadata_area_size);
            args.push("--luks2-keyslots-size");
            args.push(&keyslots_area_size);
        }

        if self.integrity {
            args.push("--integrity");
            args.push(HMAC_SHA256);
            match integrity_initialization {
                IntegrityInitialization::SkipWipeWithoutJournal => {
                    args.push("--integrity-no-wipe");
                    args.push("--integrity-no-journal");
                }
                IntegrityInitialization::CompleteWithJournal => {}
            }
        }

        args.push(device_path);
        args.push("-"); // read passphrase from stdin

        run_cryptsetup_stdin(&args, passphrase).context("cryptsetup luksFormat failed")?;
        Ok(())
    }

    /// Open a LUKS2 device using the `cryptsetup` binary.
    pub fn open_device(
        &self,
        device_path: &str,
        header_path: Option<&str>,
        name: &str,
        passphrase: &[u8],
    ) -> anyhow::Result<()> {
        let mut args: Vec<&str> = vec!["luksOpen", "-d", "-", device_path, name];

        if let Some(h) = header_path {
            args.insert(1, h);
            args.insert(1, "--header");
        }

        run_cryptsetup_stdin(&args, passphrase).context("cryptsetup luksOpen failed")?;
        debug!("device activated: {}", name);
        Ok(())
    }

    fn test_passphrase(
        &self,
        device_path: &str,
        header_path: Option<&str>,
        passphrase: &[u8],
    ) -> anyhow::Result<()> {
        let mut args = vec!["open", "--test-passphrase", "--key-file", "-"];
        if let Some(header_path) = header_path {
            args.push("--header");
            args.push(header_path);
        }
        args.push(device_path);
        run_cryptsetup_stdin(&args, passphrase).context("cryptsetup passphrase verification failed")
    }

    /// Close a LUKS2 mapping using the `cryptsetup` binary.
    pub fn close_device(&self, name: &str) -> anyhow::Result<()> {
        let args = ["luksClose", name];
        run_cryptsetup(&args).context("cryptsetup luksClose failed")?;
        Ok(())
    }
}

/// Run cryptsetup with passphrase on stdin. Does not append newline.
fn run_cryptsetup_stdin(args: &[&str], passphrase: &[u8]) -> anyhow::Result<()> {
    let _ = run_command(CRYPTSETUP_BIN, args, Some(passphrase))
        .context("failed to run cryptsetup with stdin")?;
    Ok(())
}

/// Run cryptsetup without stdin (e.g. luksClose).
fn run_cryptsetup(args: &[&str]) -> anyhow::Result<()> {
    let _ = run_command(CRYPTSETUP_BIN, args, None).context("failed to run cryptsetup")?;
    Ok(())
}

fn classify_filesystem_probe(
    success: bool,
    code: Option<i32>,
    stdout: &[u8],
    stderr: &[u8],
) -> FilesystemProbe {
    if success {
        let Ok(stdout) = std::str::from_utf8(stdout) else {
            return FilesystemProbe::Indeterminate;
        };
        let mut types = stdout.lines().filter_map(|line| line.strip_prefix("TYPE="));
        let Some(filesystem_type) = types.next() else {
            return FilesystemProbe::Indeterminate;
        };
        if filesystem_type.is_empty() || types.next().is_some() {
            return FilesystemProbe::Indeterminate;
        }
        FilesystemProbe::Filesystem(filesystem_type.to_string())
    } else if code == Some(2) && stdout.is_empty() && stderr.is_empty() {
        FilesystemProbe::Unformatted
    } else {
        FilesystemProbe::Indeterminate
    }
}

fn probe_filesystem(device_path: &str) -> Result<FilesystemProbe> {
    let output = run_command_output(
        BLKID_BIN,
        &["--probe", "--output", "export", device_path],
        None,
    )
    .context("run blkid filesystem probe")?;
    let probe = classify_filesystem_probe(
        output.status.success(),
        output.status.code(),
        &output.stdout,
        &output.stderr,
    );
    if probe == FilesystemProbe::Indeterminate {
        bail!(
            "blkid filesystem probe was indeterminate: status={}, stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        )
    }
    Ok(probe)
}

fn persistent_filesystem_action(
    state: PersistentLuksState,
    probe: &FilesystemProbe,
    expected: FsType,
) -> Result<PersistentFilesystemAction> {
    match (state, probe) {
        (PersistentLuksState::Initializing, FilesystemProbe::Unformatted) => {
            Ok(PersistentFilesystemAction::FormatThenMount)
        }
        (_, FilesystemProbe::Filesystem(filesystem_type))
            if filesystem_type == expected.as_ref() =>
        {
            Ok(PersistentFilesystemAction::MountExisting)
        }
        (_, FilesystemProbe::Filesystem(filesystem_type)) => bail!(
            "persistent device contains foreign filesystem {filesystem_type}, expected {}",
            expected.as_ref()
        ),
        (PersistentLuksState::Ready, FilesystemProbe::Unformatted) => {
            bail!("ready persistent device has no recognized filesystem")
        }
        (PersistentLuksState::Prepared, _) => {
            bail!("persistent LUKS2 header has not been committed")
        }
        (_, FilesystemProbe::Indeterminate) => {
            bail!("persistent device filesystem probe was indeterminate")
        }
    }
}

async fn block_device_region_is_zero(path: &str, offset: u64) -> Result<bool> {
    let mut device = tokio::fs::File::open(path)
        .await
        .with_context(|| format!("open block device {path} for initialization check"))?;
    device
        .seek(SeekFrom::Start(offset))
        .await
        .with_context(|| format!("seek block device {path} for initialization check"))?;
    let mut buffer = vec![0u8; ZERO_SCAN_BUFFER_SIZE];
    let mut total = 0u64;
    let mut next_progress = ZERO_SCAN_PROGRESS_INTERVAL_BYTES;
    let started = Instant::now();

    info!(
        device_path = path,
        start_offset = offset,
        "starting complete first-use zero scan before persistent LUKS2 initialization"
    );

    loop {
        let count = device
            .read(&mut buffer)
            .await
            .with_context(|| format!("read block device {path} for initialization check"))?;
        if count == 0 {
            break;
        }
        total += count as u64;
        if buffer[..count].iter().any(|byte| *byte != 0) {
            return Ok(false);
        }
        if total >= next_progress {
            info!(
                device_path = path,
                scanned_bytes = total,
                elapsed_seconds = started.elapsed().as_secs(),
                "persistent LUKS2 first-use zero scan in progress"
            );
            next_progress = next_progress.saturating_add(ZERO_SCAN_PROGRESS_INTERVAL_BYTES);
        }
    }

    if total == 0 {
        bail!("block device {path} returned no data during initialization check")
    }
    info!(
        device_path = path,
        start_offset = offset,
        scanned_bytes = total,
        elapsed_seconds = started.elapsed().as_secs(),
        "completed persistent LUKS2 first-use zero scan"
    );
    Ok(true)
}

async fn block_device_is_zero(path: &str) -> Result<bool> {
    block_device_region_is_zero(path, 0).await
}

fn open_persistent_device(path: &str) -> Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .with_context(|| format!("open persistent block device {path}"))
}

fn read_metadata_slot(device: &File, slot: usize) -> Result<[u8; PERSISTENT_METADATA_SLOT_BYTES]> {
    let mut bytes = [0u8; PERSISTENT_METADATA_SLOT_BYTES];
    device
        .read_exact_at(
            &mut bytes,
            PERSISTENT_METADATA_OFFSET_BYTES + (slot * PERSISTENT_METADATA_SLOT_BYTES) as u64,
        )
        .with_context(|| format!("read persistent LUKS2 metadata slot {slot}"))?;
    Ok(bytes)
}

fn load_persistent_metadata(
    device: &File,
    auth_key: &[u8],
    volume_id: &PersistentVolumeId,
) -> Result<Option<PersistentMetadataRecord>> {
    let mut valid = Vec::new();
    let mut invalid = Vec::new();

    for slot in 0..PERSISTENT_METADATA_SLOT_COUNT {
        match PersistentMetadataRecord::decode(
            read_metadata_slot(device, slot)?,
            auth_key,
            volume_id,
        ) {
            Ok(Some(record)) => valid.push(record),
            Ok(None) => {}
            Err(error) => invalid.push((slot, error)),
        }
    }

    if valid.is_empty() {
        if let Some((slot, error)) = invalid.into_iter().next() {
            return Err(error).with_context(|| {
                format!("persistent LUKS2 metadata slot {slot} is not authentic")
            });
        }
        return Ok(None);
    }

    for (slot, error) in invalid {
        warn!(
            metadata_slot = slot,
            %error,
            "ignoring an invalid persistent LUKS2 metadata slot"
        );
    }
    valid.sort_by_key(|record| record.sequence);
    if valid.len() == 2 && valid[0].sequence == valid[1].sequence && valid[0] != valid[1] {
        bail!("persistent LUKS2 metadata slots conflict at the same sequence")
    }
    Ok(valid.pop())
}

fn store_persistent_metadata(
    device: &File,
    record: &PersistentMetadataRecord,
    auth_key: &[u8],
) -> Result<()> {
    let slot = record
        .sequence
        .checked_sub(1)
        .context("persistent LUKS2 metadata sequence must be nonzero")? as usize
        % PERSISTENT_METADATA_SLOT_COUNT;
    let bytes = record.encode(auth_key)?;
    device
        .write_all_at(
            &bytes,
            PERSISTENT_METADATA_OFFSET_BYTES + (slot * PERSISTENT_METADATA_SLOT_BYTES) as u64,
        )
        .with_context(|| format!("write persistent LUKS2 metadata slot {slot}"))?;
    device
        .sync_data()
        .context("flush persistent LUKS2 metadata")
}

fn new_persistent_header_file_in(directory: &Path) -> Result<NamedTempFile> {
    std::fs::create_dir_all(directory).context("create protected LUKS2 header directory")?;
    let header = tempfile::Builder::new()
        .prefix("persistent-")
        .suffix(LUKS_HEADER_FILE_SUFFIX)
        .tempfile_in(directory)
        .context("create protected detached LUKS2 header")?;
    header
        .as_file()
        .set_len(PERSISTENT_HEADER_BYTES as u64)
        .context("size protected detached LUKS2 header")?;
    Ok(header)
}

fn new_persistent_header_file() -> Result<NamedTempFile> {
    new_persistent_header_file_in(Path::new(LUKS_HEADERS_STORAGE_DIR))
}

fn copy_header_and_hmac(
    source: &File,
    destination: &File,
    auth_key: &[u8],
    volume_id: &PersistentVolumeId,
) -> Result<HmacSha256> {
    let mut mac = HmacSha256::new_from_slice(auth_key).context("initialize header HMAC-SHA256")?;
    mac.update(PERSISTENT_HEADER_MAC_DOMAIN);
    mac.update(&volume_id.digest());

    let mut buffer = vec![0u8; 1024 * 1024];
    let mut offset = 0u64;
    while offset < PERSISTENT_HEADER_BYTES as u64 {
        let count =
            std::cmp::min(buffer.len() as u64, PERSISTENT_HEADER_BYTES as u64 - offset) as usize;
        source
            .read_exact_at(&mut buffer[..count], offset)
            .context("read persistent LUKS2 header")?;
        destination
            .write_all_at(&buffer[..count], offset)
            .context("write persistent LUKS2 header")?;
        mac.update(&buffer[..count]);
        offset += count as u64;
    }
    Ok(mac)
}

fn persist_header(
    device: &File,
    header: &File,
    auth_key: &[u8],
    volume_id: &PersistentVolumeId,
) -> Result<[u8; 32]> {
    let mac = copy_header_and_hmac(header, device, auth_key, volume_id)?;
    device.sync_data().context("flush detached LUKS2 header")?;
    Ok(mac.finalize().into_bytes().into())
}

fn load_verified_header_in(
    device: &File,
    record: &PersistentMetadataRecord,
    auth_key: &[u8],
    volume_id: &PersistentVolumeId,
    header_directory: &Path,
) -> Result<NamedTempFile> {
    let header = new_persistent_header_file_in(header_directory)?;
    copy_header_and_hmac(device, header.as_file(), auth_key, volume_id)?
        .verify_slice(&record.header_mac)
        .map_err(|_| anyhow::anyhow!("persistent LUKS2 header authentication failed"))?;
    Ok(header)
}

fn load_verified_header(
    device: &File,
    record: &PersistentMetadataRecord,
    auth_key: &[u8],
    volume_id: &PersistentVolumeId,
) -> Result<NamedTempFile> {
    load_verified_header_in(
        device,
        record,
        auth_key,
        volume_id,
        Path::new(LUKS_HEADERS_STORAGE_DIR),
    )
}

fn initialize_persistent_header(
    formatter: &Luks2Formatter,
    device_path: &str,
    device: &File,
    prepared: &PersistentMetadataRecord,
    auth_key: &[u8],
    key: &[u8],
    volume_id: &PersistentVolumeId,
) -> Result<(NamedTempFile, PersistentMetadataRecord)> {
    let header = new_persistent_header_file()?;
    let header_path = header
        .path()
        .to_str()
        .context("protected LUKS2 header path is not UTF-8")?;
    let started = Instant::now();
    info!(
        device_path,
        "starting persistent LUKS2 format and complete dm-integrity tag initialization"
    );
    formatter
        .encrypt_device_with_payload_alignment(
            device_path,
            Some(header_path),
            Some(PERSISTENT_DATA_OFFSET_SECTORS),
            IntegrityInitialization::CompleteWithJournal,
            key,
        )
        .context("create detached persistent LUKS2 header")?;
    info!(
        device_path,
        elapsed_seconds = started.elapsed().as_secs(),
        "completed persistent LUKS2 format and dm-integrity tag initialization"
    );
    let mac = persist_header(device, header.as_file(), auth_key, volume_id)?;
    let initializing = prepared.with_header(mac)?;
    store_persistent_metadata(device, &initializing, auth_key)?;
    Ok((header, initializing))
}

fn block_device_number(path: &str) -> Result<DeviceNumber> {
    let metadata = std::fs::metadata(path)
        .with_context(|| format!("read block device metadata for {path}"))?;
    if !metadata.file_type().is_block_device() {
        bail!("persistent LUKS2 source {path} is not a block device")
    }
    let device = metadata.rdev();
    Ok(DeviceNumber {
        major: nix::sys::stat::major(device),
        minor: nix::sys::stat::minor(device),
    })
}

fn parse_cryptsetup_status_field<'a>(output: &'a str, field: &str) -> Option<&'a str> {
    output.lines().find_map(|line| {
        let (name, value) = line.trim().split_once(':')?;
        (name == field).then_some(value.trim())
    })
}

fn persistent_mapper_backing_path(output: &str) -> Result<&str> {
    let mapping_type = parse_cryptsetup_status_field(output, "type")
        .context("cryptsetup status did not identify the mapper type")?;
    if mapping_type != "LUKS2" {
        bail!("persistent mapper name is active for a non-LUKS2 mapping")
    }
    let integrity = parse_cryptsetup_status_field(output, "integrity")
        .context("cryptsetup status did not identify the mapper integrity algorithm")?;
    if integrity != HMAC_SHA256_STATUS {
        bail!("persistent mapper reported unexpected integrity algorithm {integrity:?}")
    }
    parse_cryptsetup_status_field(output, "device")
        .context("cryptsetup status did not identify the mapper backing device")
}

fn verify_existing_mapper(
    formatter: &Luks2Formatter,
    device_path: &str,
    header_path: &str,
    expected_device: DeviceNumber,
    mapper_name: &str,
    key: &[u8],
) -> Result<()> {
    formatter
        .test_passphrase(device_path, Some(header_path), key)
        .context("verify key for existing persistent mapper")?;

    let (stdout, _) = run_command(CRYPTSETUP_BIN, &["status", mapper_name], None)
        .context("inspect existing persistent mapper")?;
    let backing_path = persistent_mapper_backing_path(&stdout)?;
    let actual_device = block_device_number(backing_path)?;
    if actual_device != expected_device {
        bail!("persistent mapper name is active for another block device")
    }
    Ok(())
}

fn decode_mountinfo_path(input: &str) -> String {
    let input = input.as_bytes();
    let mut output = Vec::with_capacity(input.len());
    let mut index = 0;
    while index < input.len() {
        if input[index] == b'\\'
            && index + 3 < input.len()
            && input[index + 1..=index + 3]
                .iter()
                .all(|byte| matches!(byte, b'0'..=b'7'))
        {
            let value = (input[index + 1] - b'0') * 64
                + (input[index + 2] - b'0') * 8
                + (input[index + 3] - b'0');
            output.push(value);
            index += 4;
        } else {
            output.push(input[index]);
            index += 1;
        }
    }
    String::from_utf8_lossy(&output).into_owned()
}

fn mounted_filesystem_from_mountinfo(
    mountinfo: &str,
    mount_point: &str,
) -> Result<Option<MountedFilesystem>> {
    for line in mountinfo.lines() {
        let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
        if fields.len() < 6 || decode_mountinfo_path(fields[4]) != mount_point {
            continue;
        }
        let separator = fields
            .iter()
            .position(|field| *field == "-")
            .context("mountinfo entry has no filesystem separator")?;
        let filesystem_type = fields
            .get(separator + 1)
            .context("mountinfo entry has no filesystem type")?;
        let (major, minor) = fields[2]
            .split_once(':')
            .context("mountinfo has an invalid device number")?;
        return Ok(Some(MountedFilesystem {
            device: DeviceNumber {
                major: major.parse().context("parse mountinfo major number")?,
                minor: minor.parse().context("parse mountinfo minor number")?,
            },
            filesystem_type: (*filesystem_type).to_string(),
        }));
    }
    Ok(None)
}

fn mounted_filesystem_at(mount_point: &str) -> Result<Option<MountedFilesystem>> {
    let mountinfo =
        std::fs::read_to_string("/proc/self/mountinfo").context("read /proc/self/mountinfo")?;
    mounted_filesystem_from_mountinfo(&mountinfo, mount_point)
}

fn mount_filesystem(device_path: &str, mount_point: &str, fs_type: FsType) -> Result<()> {
    mount::<_, _, str, _>(
        Some(device_path),
        mount_point,
        Some(fs_type.as_ref()),
        MsFlags::MS_NOATIME,
        Some(""),
    )
    .with_context(|| format!("mount persistent device {device_path} at {mount_point}"))
}

async fn prepare_persistent_mount_point(mount_point: &str) -> Result<()> {
    tokio::fs::create_dir_all(mount_point)
        .await
        .with_context(|| format!("create persistent mount point {mount_point}"))?;

    let metadata = tokio::fs::symlink_metadata(mount_point)
        .await
        .with_context(|| format!("inspect persistent mount point {mount_point}"))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        bail!("persistent mount point must be a directory, not a symlink")
    }

    let canonical = tokio::fs::canonicalize(mount_point)
        .await
        .with_context(|| format!("resolve persistent mount point {mount_point}"))?;
    if canonical != Path::new(mount_point) {
        bail!("persistent mount point must not contain symlink components")
    }
    Ok(())
}

#[derive(Default)]
struct PersistentMountTransaction {
    mapper_name: String,
    mount_point: String,
    opened_mapper: bool,
    mounted_filesystem: bool,
}

impl PersistentMountTransaction {
    fn rollback(&self) {
        if self.mounted_filesystem {
            if let Err(error) = nix::mount::umount(self.mount_point.as_str()) {
                warn!(
                    mount_point = %self.mount_point,
                    %error,
                    "failed to roll back persistent filesystem mount"
                );
            }
        }
        if self.opened_mapper {
            if let Err(error) = Luks2Formatter::default().close_device(&self.mapper_name) {
                warn!(
                    mapper_name = %self.mapper_name,
                    %error,
                    "failed to roll back persistent LUKS2 mapper"
                );
            }
        }
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct Luks2MountParameters {
    /// Indicates whether to enable dm-integrity.
    ///
    /// When this is true and CDH formats an empty ext4 filesystem, CDH uses
    /// integrity-compatible formatting and applies ext4 safety defaults such as
    /// lazy_itable_init=0 unless the caller explicitly provides that option in
    /// mkfsOpts.
    #[serde(rename = "dataIntegrity")]
    #[serde(default)]
    pub data_integrity: Option<String>,

    /// Optional name for /dev/mapper/<name>
    #[serde(rename = "mapperName")]
    pub mapper_name: Option<String>,

    /// The type of the target mount point.
    /// Either `device` or `fileSystem`.
    #[serde(rename = "targetType")]
    #[serde(flatten)]
    pub target_type: TargetType,
}

impl Luks2MountParameters {
    pub(crate) fn validate_persistent(&self) -> std::result::Result<(), &'static str> {
        if self.mapper_name.is_some() {
            return Err("mapperName is derived from volumeId and must be omitted");
        }
        match self.data_integrity.as_deref() {
            Some("true") => {}
            None | Some("false") => return Err("persistent mode requires dataIntegrity=true"),
            Some(_) => return Err("dataIntegrity must be true or false"),
        }
        match &self.target_type {
            TargetType::Device => {
                return Err("persistent mode currently requires a filesystem target")
            }
            TargetType::FileSystem {
                mkfs_opts: Some(_), ..
            } => return Err("mkfsOpts are not accepted by persistent mode"),
            TargetType::FileSystem {
                mkfs_opts: None, ..
            } => {}
        }
        Ok(())
    }

    /// Initialize or reopen a persistent LUKS2 filesystem.
    ///
    /// The host controls the block device, including its LUKS2 metadata. CDH
    /// therefore authenticates the complete header and gives cryptsetup only a
    /// verified detached copy held under `/run`. Two authenticated state slots
    /// allow initialization to resume after an interrupted write. They do not
    /// prevent the host from replaying an older, valid disk image.
    pub(crate) async fn do_mount_persistent(
        self,
        device_path: &str,
        mount_point: &str,
        key: Zeroizing<Vec<u8>>,
        volume_id: PersistentVolumeId,
    ) -> Result<()> {
        self.validate_persistent().map_err(anyhow::Error::msg)?;
        validate_persistent_key(&key)?;
        let filesystem_type = match self.target_type {
            TargetType::FileSystem {
                filesystem_type, ..
            } => filesystem_type,
            TargetType::Device => unreachable!("persistent parameters validated above"),
        };

        prepare_persistent_mount_point(mount_point).await?;

        let source_device = block_device_number(device_path)?;
        let device_lock = PERSISTENT_MOUNT_LOCKS.for_device(source_device).await;
        let _device_guard = device_lock.lock_owned().await;
        let mapper_name = volume_id.mapper_name();
        let mapper_path = format!("/dev/mapper/{mapper_name}");
        let mapper_exists = Path::new(&mapper_path).exists();
        let formatter = Luks2Formatter::default().with_integrity(true);

        let device = open_persistent_device(device_path)?;
        let auth_key = derive_persistent_auth_key(&key, &volume_id)?;
        let existing_record = load_persistent_metadata(&device, &auth_key, &volume_id)?;
        let (header, record) = match existing_record {
            Some(record) if record.state == PersistentLuksState::Prepared => {
                if mapper_exists {
                    bail!("persistent mapper exists before its LUKS2 header was committed")
                }
                if !block_device_region_is_zero(device_path, PERSISTENT_DATA_OFFSET_BYTES).await? {
                    bail!("prepared persistent LUKS2 device contains nonzero payload data")
                }
                initialize_persistent_header(
                    &formatter,
                    device_path,
                    &device,
                    &record,
                    &auth_key,
                    &key,
                    &volume_id,
                )?
            }
            Some(record) => {
                let header = load_verified_header(&device, &record, &auth_key, &volume_id)?;
                (header, record)
            }
            None => {
                if mapper_exists {
                    bail!("persistent mapper exists for a device with no CDH metadata")
                }
                if !block_device_is_zero(device_path).await? {
                    bail!("refusing to initialize a nonzero block device without CDH metadata")
                }
                let prepared = PersistentMetadataRecord::prepared(&volume_id);
                store_persistent_metadata(&device, &prepared, &auth_key)?;
                initialize_persistent_header(
                    &formatter,
                    device_path,
                    &device,
                    &prepared,
                    &auth_key,
                    &key,
                    &volume_id,
                )?
            }
        };
        let state = record.state;
        let header_path = header
            .path()
            .to_str()
            .context("protected LUKS2 header path is not UTF-8")?;

        let mut transaction = PersistentMountTransaction {
            mapper_name: mapper_name.clone(),
            mount_point: mount_point.to_string(),
            ..Default::default()
        };

        let result = (|| -> Result<()> {
            if mapper_exists {
                verify_existing_mapper(
                    &formatter,
                    device_path,
                    header_path,
                    source_device,
                    &mapper_name,
                    &key,
                )?;
            } else {
                formatter
                    .open_device(device_path, Some(header_path), &mapper_name, &key)
                    .context("open persistent LUKS2 device")?;
                transaction.opened_mapper = true;
            }

            let mapper_device = block_device_number(&mapper_path)?;
            let already_mounted = match mounted_filesystem_at(mount_point)? {
                Some(mounted)
                    if mounted.device == mapper_device
                        && mounted.filesystem_type == filesystem_type.as_ref() =>
                {
                    true
                }
                Some(mounted) if mounted.device == mapper_device => {
                    bail!(
                        "persistent mount point has filesystem type {}, expected {}",
                        mounted.filesystem_type,
                        filesystem_type.as_ref()
                    )
                }
                Some(_) => bail!("persistent mount point is active for another device"),
                None => false,
            };

            if !already_mounted {
                let filesystem_probe = probe_filesystem(&mapper_path)?;
                match persistent_filesystem_action(state, &filesystem_probe, filesystem_type)? {
                    PersistentFilesystemAction::MountExisting => {
                        mount_filesystem(&mapper_path, mount_point, filesystem_type)
                            .context("mount existing persistent filesystem")?;
                        transaction.mounted_filesystem = true;
                    }
                    PersistentFilesystemAction::FormatThenMount => {
                        let fs_formatter = FsFormatter {
                            fs_type: filesystem_type,
                            force: true,
                            args: Vec::new(),
                        };
                        fs_formatter
                            .format_with_eager_inode_initialization(&mapper_path)
                            .context("create persistent ext4 filesystem")?;
                        mount_filesystem(&mapper_path, mount_point, filesystem_type)
                            .context("mount initialized persistent filesystem")?;
                        transaction.mounted_filesystem = true;
                    }
                }
            }

            if state == PersistentLuksState::Initializing {
                File::open(&mapper_path)
                    .context("open initialized persistent mapper for flush")?
                    .sync_all()
                    .context("flush initialized persistent filesystem")?;
                store_persistent_metadata(&device, &record.ready()?, &auth_key)
                    .context("commit persistent LUKS2 initialization")?;
            }

            Ok(())
        })();

        if result.is_err() {
            transaction.rollback();
        }
        result
    }

    /// Do the mount operation for the LUKS2 device.
    /// Returns the header path if the source type is empty.
    pub async fn do_mount(
        self,
        device_path: &str,
        mount_point: &str,
        key: Zeroizing<Vec<u8>>,
        source_type: SourceType,
    ) -> Result<Option<String>> {
        let data_integrity = self.data_integrity.map(|s| s == "true").unwrap_or(false);
        let formatter = Luks2Formatter::default().with_integrity(data_integrity);
        // 3.1 if the source type is empty, encrypt the device and create detached header
        let header_path = if source_type == SourceType::Empty {
            warn!("encrypting the device. This will wipe original data on the disk.");
            let header_path = luks_header_path(device_path);
            prepare_luks_header_file(&header_path)?;
            formatter
                .encrypt_device(device_path, Some(&header_path), &key)
                .context("Failed to encrypt LUKS2 device")?;
            Some(header_path)
        } else {
            None
        };

        let devmapper_name = self.mapper_name.unwrap_or_else(|| {
            debug!("No mapper name provided, generating a random one");
            uuid::Uuid::new_v4().to_string()
        });

        debug!(device_path = device_path, "luks2 opening device");
        formatter
            .open_device(device_path, header_path.as_deref(), &devmapper_name, &key)
            .context("Failed to open LUKS2 device")?;

        let dev_path = format!("/dev/mapper/{}", devmapper_name);
        match (self.target_type, source_type) {
            // 3.2 if the target type is device, do the symlink operation to map
            // the device path to the mount point.
            (TargetType::Device, _) => {
                info!(
                    "symlinking device: {} to mount point: {}",
                    dev_path, mount_point
                );
                symlink(&dev_path, mount_point).await.with_context(|| {
                    format!(
                        "Failed to create symlink from {} to {}",
                        dev_path, mount_point
                    )
                })?;
                debug!(mount_point = mount_point, "created symlink");
            }
            // 3.3 if the source type is encrypted, meaning that there is
            // already a filesystem on the device, so we just need to mount it to the mount point.
            (
                TargetType::FileSystem {
                    filesystem_type, ..
                },
                SourceType::Encrypted,
            ) => {
                info!(
                    "mounting device: {} to mount point: {}",
                    dev_path, mount_point
                );
                mount::<_, _, str, _>(
                    Some(&dev_path[..]),
                    mount_point,
                    Some(filesystem_type.as_ref()),
                    MsFlags::MS_NOATIME,
                    Some(""),
                )
                .with_context(|| {
                    format!(
                        "Failed to mount device {} to mount point {}",
                        dev_path, mount_point
                    )
                })?;

                debug!(mount_point = mount_point, "mounted device");
            }
            // 3.4 if the source type is empty, meaning that we should also make
            // a filesystem on the device.
            (
                TargetType::FileSystem {
                    filesystem_type,
                    mkfs_opts,
                },
                SourceType::Empty,
            ) => {
                info!(
                    "formatting device: {} and mounting it to mount point: {}",
                    dev_path, mount_point
                );
                let args = mkfs_opts
                    .map(|s| {
                        s.split_ascii_whitespace()
                            .map(|x| x.to_string())
                            .collect::<Vec<String>>()
                    })
                    .unwrap_or_default();
                debug!(
                    device_path = dev_path,
                    filesystem_type = ?filesystem_type,
                    args = ?args,
                    "formatting device"
                );
                let fs_formatter = FsFormatter {
                    fs_type: filesystem_type,
                    force: true,
                    args,
                };

                let format_result = if data_integrity {
                    fs_formatter.format_integrity_compatible(&dev_path)
                } else {
                    fs_formatter.format(&dev_path)
                };
                format_result.with_context(|| {
                    format!(
                        "Failed to make filesystem {:?} of device {}",
                        filesystem_type, dev_path
                    )
                })?;

                debug!(device_path = dev_path, "mounting device");
                mount(
                    Some(&dev_path[..]),
                    mount_point,
                    Some(filesystem_type.as_ref()),
                    MsFlags::MS_NOATIME,
                    Some(""),
                )
                .with_context(|| {
                    format!(
                        "Failed to mount device {} to mount point {}",
                        dev_path, mount_point
                    )
                })?;
                debug!(mount_point = mount_point, "mounted device");
            }
            (TargetType::FileSystem { .. }, SourceType::Persistent) => {
                bail!("persistent source type must use the persistent LUKS2 workflow")
            }
        }
        Ok(header_path)
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};

    use serial_test::serial;
    use zeroize::Zeroizing;

    use crate::storage::drivers::TempFileLoopDevice;

    use super::*;

    const TEST_PASSPHRASE: &[u8] = b"test";
    const NAME: &str = "test";

    fn persistent_parameters() -> Luks2MountParameters {
        Luks2MountParameters {
            data_integrity: Some("true".to_string()),
            mapper_name: None,
            target_type: TargetType::FileSystem {
                filesystem_type: FsType::Ext4,
                mkfs_opts: None,
            },
        }
    }

    #[tokio::test]
    async fn persistent_mount_locks_are_scoped_per_device() {
        let locks = PersistentMountLocks::default();
        let first_device = DeviceNumber { major: 8, minor: 1 };
        let second_device = DeviceNumber { major: 8, minor: 2 };

        let first = locks.for_device(first_device).await;
        let alias = locks.for_device(first_device).await;
        let other = locks.for_device(second_device).await;

        assert!(Arc::ptr_eq(&first, &alias));
        assert!(!Arc::ptr_eq(&first, &other));

        let _guard = first.clone().lock_owned().await;
        assert!(alias.try_lock().is_err());
        assert!(other.try_lock().is_ok());
    }

    #[test]
    fn persistent_volume_identity_is_strict_and_deterministic() {
        let id = PersistentVolumeId::try_from("tenant/example/web-data").unwrap();
        let same = PersistentVolumeId::try_from("tenant/example/web-data").unwrap();
        let other = PersistentVolumeId::try_from("tenant/example/database").unwrap();

        assert_eq!(id.mapper_name(), same.mapper_name());
        assert_ne!(id.mapper_name(), other.mapper_name());
        assert!(id.mapper_name().starts_with(PERSISTENT_MAPPER_PREFIX));
        assert!(id.mapper_name().len() < 128);

        let too_long = "a".repeat(PERSISTENT_VOLUME_ID_MAX_BYTES + 1);
        for invalid in [
            "",
            "contains space",
            "unicode-☃",
            "/leading",
            "trailing/",
            "two//segments",
            "parent/../segment",
        ] {
            assert!(
                PersistentVolumeId::try_from(invalid).is_err(),
                "accepted invalid persistent volume ID: {invalid:?}"
            );
        }
        assert!(PersistentVolumeId::try_from(too_long.as_str()).is_err());
    }

    #[test]
    fn filesystem_probe_requires_conclusive_results() {
        assert_eq!(
            classify_filesystem_probe(true, Some(0), b"TYPE=ext4\n", b""),
            FilesystemProbe::Filesystem("ext4".to_string())
        );
        assert_eq!(
            classify_filesystem_probe(false, Some(2), b"", b""),
            FilesystemProbe::Unformatted
        );

        for probe in [
            classify_filesystem_probe(false, Some(2), b"", b"read error"),
            classify_filesystem_probe(false, Some(8), b"", b"ambivalent"),
            classify_filesystem_probe(false, None, b"", b"terminated"),
            classify_filesystem_probe(true, Some(0), b"UUID=value\n", b""),
            classify_filesystem_probe(true, Some(0), b"TYPE=ext4\nTYPE=xfs\n", b""),
        ] {
            assert_eq!(probe, FilesystemProbe::Indeterminate);
        }
    }

    #[test]
    fn persistent_format_authority_is_state_and_probe_bound() {
        assert_eq!(
            persistent_filesystem_action(
                PersistentLuksState::Initializing,
                &FilesystemProbe::Unformatted,
                FsType::Ext4,
            )
            .unwrap(),
            PersistentFilesystemAction::FormatThenMount
        );
        assert_eq!(
            persistent_filesystem_action(
                PersistentLuksState::Initializing,
                &FilesystemProbe::Filesystem("ext4".to_string()),
                FsType::Ext4,
            )
            .unwrap(),
            PersistentFilesystemAction::MountExisting
        );
        assert_eq!(
            persistent_filesystem_action(
                PersistentLuksState::Ready,
                &FilesystemProbe::Filesystem("ext4".to_string()),
                FsType::Ext4,
            )
            .unwrap(),
            PersistentFilesystemAction::MountExisting
        );

        for (state, probe) in [
            (PersistentLuksState::Prepared, FilesystemProbe::Unformatted),
            (PersistentLuksState::Ready, FilesystemProbe::Unformatted),
            (
                PersistentLuksState::Initializing,
                FilesystemProbe::Filesystem("xfs".to_string()),
            ),
            (
                PersistentLuksState::Initializing,
                FilesystemProbe::Indeterminate,
            ),
            (PersistentLuksState::Ready, FilesystemProbe::Indeterminate),
        ] {
            assert!(persistent_filesystem_action(state, &probe, FsType::Ext4).is_err());
        }
    }

    #[test]
    fn persistent_metadata_is_authenticated_and_volume_bound() {
        let id = PersistentVolumeId::try_from("tenant/example/web-data").unwrap();
        let other = PersistentVolumeId::try_from("tenant/example/database").unwrap();
        let key = derive_persistent_auth_key(b"volume key", &id).unwrap();
        let prepared = PersistentMetadataRecord::prepared(&id);
        let encoded = prepared.encode(&key).unwrap();

        assert_eq!(
            PersistentMetadataRecord::decode(encoded, &key, &id)
                .unwrap()
                .unwrap(),
            prepared
        );
        assert!(PersistentMetadataRecord::decode(encoded, &key, &other).is_err());

        let wrong_key = derive_persistent_auth_key(b"wrong key", &id).unwrap();
        assert!(PersistentMetadataRecord::decode(encoded, &wrong_key, &id).is_err());

        let mut tampered = encoded;
        tampered[52] ^= 1;
        assert!(PersistentMetadataRecord::decode(tampered, &key, &id).is_err());
    }

    #[test]
    fn persistent_metadata_recovers_the_last_complete_slot() {
        let device = tempfile::tempfile().unwrap();
        device.set_len(PERSISTENT_DATA_OFFSET_BYTES + 4096).unwrap();
        let id = PersistentVolumeId::try_from("tenant/example/web-data").unwrap();
        let key = derive_persistent_auth_key(b"volume key", &id).unwrap();
        let prepared = PersistentMetadataRecord::prepared(&id);
        store_persistent_metadata(&device, &prepared, &key).unwrap();
        let initializing = prepared.with_header([7; 32]).unwrap();
        store_persistent_metadata(&device, &initializing, &key).unwrap();

        assert_eq!(
            load_persistent_metadata(&device, &key, &id)
                .unwrap()
                .unwrap(),
            initializing
        );

        device
            .write_all_at(&[0xa5; 128], PERSISTENT_METADATA_OFFSET_BYTES)
            .expect("corrupt older metadata slot");
        assert_eq!(
            load_persistent_metadata(&device, &key, &id)
                .unwrap()
                .unwrap(),
            initializing
        );
    }

    #[test]
    fn persistent_header_tampering_is_rejected() {
        let header_directory = tempfile::tempdir().unwrap();
        let device = tempfile::tempfile().unwrap();
        device.set_len(PERSISTENT_DATA_OFFSET_BYTES + 4096).unwrap();
        let header = tempfile::tempfile().unwrap();
        header.set_len(LUKS2_HEADER_MIN_SIZE_BYTES).unwrap();
        header.write_all_at(b"LUKS header", 0).unwrap();

        let id = PersistentVolumeId::try_from("tenant/example/web-data").unwrap();
        let key = derive_persistent_auth_key(b"volume key", &id).unwrap();
        let prepared = PersistentMetadataRecord::prepared(&id);
        let record = prepared
            .with_header(persist_header(&device, &header, &key, &id).unwrap())
            .unwrap();
        assert!(
            load_verified_header_in(&device, &record, &key, &id, header_directory.path(),).is_ok()
        );

        device.write_all_at(b"X", 4).unwrap();
        let error = load_verified_header_in(&device, &record, &key, &id, header_directory.path())
            .unwrap_err();
        assert!(error
            .to_string()
            .contains("persistent LUKS2 header authentication failed"));
    }

    #[test]
    fn persistent_parameter_subset_rejects_unsafe_options() {
        assert!(persistent_parameters().validate_persistent().is_ok());

        let mut parameters = persistent_parameters();
        parameters.mapper_name = Some("caller-controlled".to_string());
        assert!(parameters.validate_persistent().is_err());

        let mut parameters = persistent_parameters();
        parameters.data_integrity = Some("false".to_string());
        assert!(parameters.validate_persistent().is_err());

        let mut parameters = persistent_parameters();
        parameters.data_integrity = None;
        assert!(parameters.validate_persistent().is_err());

        let mut parameters = persistent_parameters();
        parameters.data_integrity = Some("not-a-bool".to_string());
        assert!(parameters.validate_persistent().is_err());

        let mut parameters = persistent_parameters();
        parameters.target_type = TargetType::Device;
        assert!(parameters.validate_persistent().is_err());

        let mut parameters = persistent_parameters();
        parameters.target_type = TargetType::FileSystem {
            filesystem_type: FsType::Ext4,
            mkfs_opts: Some("-F /dev/other".to_string()),
        };
        assert!(parameters.validate_persistent().is_err());
    }

    #[test]
    fn persistent_key_size_is_bounded() {
        assert!(validate_persistent_key(&[0; PERSISTENT_KEY_MIN_BYTES]).is_ok());
        assert!(validate_persistent_key(&[0; PERSISTENT_KEY_MAX_BYTES]).is_ok());
        assert!(validate_persistent_key(&[0; PERSISTENT_KEY_MIN_BYTES - 1]).is_err());
        assert!(validate_persistent_key(&vec![0; PERSISTENT_KEY_MAX_BYTES + 1]).is_err());
    }

    #[test]
    fn parsers_require_exact_mapper_and_mount_identity() {
        let status = concat!(
            "/dev/mapper/coco-pv-test is active.\n",
            "  type: LUKS2\n",
            "  integrity: hmac(sha256)\n",
            "  device: /dev/vdb\n",
        );
        assert_eq!(parse_cryptsetup_status_field(status, "type"), Some("LUKS2"));
        assert_eq!(
            parse_cryptsetup_status_field(status, "device"),
            Some("/dev/vdb")
        );
        assert_eq!(persistent_mapper_backing_path(status).unwrap(), "/dev/vdb");
        assert!(persistent_mapper_backing_path("type: PLAIN\ndevice: /dev/vdb\n").is_err());
        assert!(persistent_mapper_backing_path("type: LUKS2\ndevice: /dev/vdb\n").is_err());
        assert!(persistent_mapper_backing_path(
            "type: LUKS2\nintegrity: crc32c\ndevice: /dev/vdb\n"
        )
        .is_err());
        assert_eq!(
            parse_cryptsetup_status_field("type: LUKS2\n", "device"),
            None
        );

        let mountinfo = concat!(
            "35 24 0:31 / /run rw,nosuid - tmpfs tmpfs rw\n",
            "36 35 253:7 / /run/secure\\040volume rw,noatime - ext4 /dev/mapper/coco-pv-test rw\n"
        );
        assert_eq!(
            mounted_filesystem_from_mountinfo(mountinfo, "/run/secure volume").unwrap(),
            Some(MountedFilesystem {
                device: DeviceNumber {
                    major: 253,
                    minor: 7
                },
                filesystem_type: "ext4".to_string()
            })
        );
        assert_eq!(
            mounted_filesystem_from_mountinfo(mountinfo, "/run/not-mounted").unwrap(),
            None
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn persistent_mount_point_rejects_symlinks() {
        let directory = tempfile::tempdir().unwrap();
        let direct = directory.path().join("direct");
        prepare_persistent_mount_point(direct.to_str().unwrap())
            .await
            .unwrap();

        let symlink = directory.path().join("symlink");
        tokio::fs::symlink(&direct, &symlink).await.unwrap();
        assert!(prepare_persistent_mount_point(symlink.to_str().unwrap())
            .await
            .is_err());

        let real_parent = directory.path().join("real-parent");
        tokio::fs::create_dir(&real_parent).await.unwrap();
        let parent_symlink = directory.path().join("parent-symlink");
        tokio::fs::symlink(&real_parent, &parent_symlink)
            .await
            .unwrap();
        let child = parent_symlink.join("child");
        assert!(prepare_persistent_mount_point(child.to_str().unwrap())
            .await
            .is_err());
    }

    #[tokio::test]
    async fn zero_scan_reads_the_complete_device() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let path = file.path();
        tokio::fs::write(path, vec![0u8; ZERO_SCAN_BUFFER_SIZE + 1])
            .await
            .unwrap();
        assert!(block_device_is_zero(path.to_str().unwrap()).await.unwrap());

        let mut data = vec![0u8; ZERO_SCAN_BUFFER_SIZE + 1];
        *data.last_mut().unwrap() = 1;
        tokio::fs::write(path, data).await.unwrap();
        assert!(!block_device_is_zero(path.to_str().unwrap()).await.unwrap());

        tokio::fs::write(path, [1, 2, 3, 4, 0, 0, 0, 0])
            .await
            .unwrap();
        assert!(block_device_region_is_zero(path.to_str().unwrap(), 4)
            .await
            .unwrap());

        tokio::fs::write(path, []).await.unwrap();
        assert!(block_device_is_zero(path.to_str().unwrap()).await.is_err());
    }

    /// Removes the LUKS header file on drop so tests don't leave files behind on panic.
    struct RemoveHeaderOnDrop(String);
    impl Drop for RemoveHeaderOnDrop {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    /// Closes the dm-crypt device on drop so tests don't leave mapper devices behind.
    struct CloseDeviceOnDrop(String);
    impl Drop for CloseDeviceOnDrop {
        fn drop(&mut self) {
            let _ = Luks2Formatter::default().close_device(&self.0);
        }
    }

    struct PersistentResourcesOnDrop {
        mapper_name: String,
        mount_point: String,
    }

    impl Drop for PersistentResourcesOnDrop {
        fn drop(&mut self) {
            let _ = nix::mount::umount(self.mount_point.as_str());
            let _ = Luks2Formatter::default().close_device(&self.mapper_name);
        }
    }

    fn persistent_state(
        device_path: &str,
        key: &[u8],
        volume_id: &PersistentVolumeId,
    ) -> PersistentLuksState {
        let device = open_persistent_device(device_path).unwrap();
        let auth_key = derive_persistent_auth_key(key, volume_id).unwrap();
        load_persistent_metadata(&device, &auth_key, volume_id)
            .unwrap()
            .unwrap()
            .state
    }

    fn device_digest(device_path: &str) -> [u8; 32] {
        let mut device = File::open(device_path).unwrap();
        let mut hasher = Sha256::new();
        let mut buffer = vec![0u8; 1024 * 1024];
        loop {
            let count = device.read(&mut buffer).unwrap();
            if count == 0 {
                break;
            }
            hasher.update(&buffer[..count]);
        }
        hasher.finalize().into()
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "requires root, cryptsetup, loop devices, and mount privileges"]
    #[serial]
    async fn persistent_luks2_loop_lifecycle_and_init_recovery() {
        let device = TempFileLoopDevice::new(128 * 1024 * 1024).unwrap();
        let mount_directory = tempfile::tempdir().unwrap();
        let mount_point = mount_directory.path().to_str().unwrap();
        let volume_id = PersistentVolumeId::try_from("tenant/workload/test-volume").unwrap();
        let mapper_name = volume_id.mapper_name();
        let _resources = PersistentResourcesOnDrop {
            mapper_name: mapper_name.clone(),
            mount_point: mount_point.to_string(),
        };
        let key = b"persistent-test-data-encryption-key";

        persistent_parameters()
            .do_mount_persistent(
                device.dev_path(),
                mount_point,
                Zeroizing::new(key.to_vec()),
                volume_id.clone(),
            )
            .await
            .unwrap();
        let (status, _) = run_command(CRYPTSETUP_BIN, &["status", &mapper_name], None).unwrap();
        assert_eq!(
            persistent_mapper_backing_path(&status).unwrap(),
            device.dev_path()
        );
        std::fs::write(mount_directory.path().join("sentinel"), b"preserve me").unwrap();
        nix::mount::umount(mount_point).unwrap();
        Luks2Formatter::default()
            .close_device(&mapper_name)
            .unwrap();
        assert_eq!(
            persistent_state(device.dev_path(), key, &volume_id),
            PersistentLuksState::Ready
        );

        // Dropping the newest slot models power loss while committing `ready`.
        // Recovery must use the older authenticated header without reformatting.
        open_persistent_device(device.dev_path())
            .unwrap()
            .write_all_at(
                &[0; PERSISTENT_METADATA_SLOT_BYTES],
                PERSISTENT_METADATA_OFFSET_BYTES,
            )
            .unwrap();
        assert_eq!(
            persistent_state(device.dev_path(), key, &volume_id),
            PersistentLuksState::Initializing
        );
        persistent_parameters()
            .do_mount_persistent(
                device.dev_path(),
                mount_point,
                Zeroizing::new(key.to_vec()),
                volume_id.clone(),
            )
            .await
            .unwrap();
        assert_eq!(
            std::fs::read(mount_directory.path().join("sentinel")).unwrap(),
            b"preserve me"
        );
        nix::mount::umount(mount_point).unwrap();
        Luks2Formatter::default()
            .close_device(&mapper_name)
            .unwrap();
        assert_eq!(
            persistent_state(device.dev_path(), key, &volume_id),
            PersistentLuksState::Ready
        );

        assert!(persistent_parameters()
            .do_mount_persistent(
                device.dev_path(),
                mount_point,
                Zeroizing::new(b"wrong key".to_vec()),
                volume_id,
            )
            .await
            .is_err());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "requires root, cryptsetup, loop devices, mkfs, blkid, and mount privileges"]
    #[serial]
    async fn persistent_luks2_rejects_a_modified_header_before_opening_it() {
        let device = TempFileLoopDevice::new(128 * 1024 * 1024).unwrap();
        let mount_directory = tempfile::tempdir().unwrap();
        let mount_point = mount_directory.path().to_str().unwrap();
        let volume_id = PersistentVolumeId::try_from("tenant/workload/tamper-test").unwrap();
        let mapper_name = volume_id.mapper_name();
        let _resources = PersistentResourcesOnDrop {
            mapper_name: mapper_name.clone(),
            mount_point: mount_point.to_string(),
        };
        let key = b"persistent-header-tamper-test-key";

        persistent_parameters()
            .do_mount_persistent(
                device.dev_path(),
                mount_point,
                Zeroizing::new(key.to_vec()),
                volume_id.clone(),
            )
            .await
            .unwrap();
        nix::mount::umount(mount_point).unwrap();
        Luks2Formatter::default()
            .close_device(&mapper_name)
            .unwrap();

        let device_file = open_persistent_device(device.dev_path()).unwrap();
        let tamper_offset = PERSISTENT_HEADER_BYTES as u64 - 1;
        let mut byte = [0];
        device_file.read_exact_at(&mut byte, tamper_offset).unwrap();
        byte[0] ^= 1;
        device_file.write_all_at(&byte, tamper_offset).unwrap();
        let error = persistent_parameters()
            .do_mount_persistent(
                device.dev_path(),
                mount_point,
                Zeroizing::new(key.to_vec()),
                volume_id,
            )
            .await
            .unwrap_err();

        assert!(format!("{error:#}").contains("persistent LUKS2 header authentication failed"));
        assert!(!Path::new(&format!("/dev/mapper/{mapper_name}")).exists());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "requires root, loop devices, and block-device access"]
    #[serial]
    async fn interrupted_persistent_integrity_format_fails_without_mutation() {
        let device = TempFileLoopDevice::new(128 * 1024 * 1024).unwrap();
        let mount_directory = tempfile::tempdir().unwrap();
        let mount_point = mount_directory.path().to_str().unwrap();
        let volume_id = PersistentVolumeId::try_from("tenant/workload/interrupted-format").unwrap();
        let mapper_name = volume_id.mapper_name();
        let key = b"persistent-interrupted-format-test-key";
        let source = open_persistent_device(device.dev_path()).unwrap();
        let auth_key = derive_persistent_auth_key(key, &volume_id).unwrap();
        let prepared = PersistentMetadataRecord::prepared(&volume_id);
        store_persistent_metadata(&source, &prepared, &auth_key).unwrap();

        // cryptsetup writes the dm-integrity superblock before it can return a
        // complete detached header. A power loss there must never authorize a
        // destructive retry against the now-nonzero device.
        source
            .write_all_at(&[0x5a], PERSISTENT_DATA_OFFSET_BYTES)
            .unwrap();
        source.sync_all().unwrap();
        let before = device_digest(device.dev_path());

        let error = persistent_parameters()
            .do_mount_persistent(
                device.dev_path(),
                mount_point,
                Zeroizing::new(key.to_vec()),
                volume_id,
            )
            .await
            .unwrap_err();

        assert!(format!("{error:#}")
            .contains("prepared persistent LUKS2 device contains nonzero payload data"));
        assert_eq!(device_digest(device.dev_path()), before);
        assert!(!Path::new(&format!("/dev/mapper/{mapper_name}")).exists());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "requires root, cryptsetup, loop devices, mkfs, blkid, and mount privileges"]
    #[serial]
    async fn persistent_luks2_detects_corrupted_payload() {
        let device = TempFileLoopDevice::new(128 * 1024 * 1024).unwrap();
        let mount_directory = tempfile::tempdir().unwrap();
        let mount_point = mount_directory.path().to_str().unwrap();
        let volume_id = PersistentVolumeId::try_from("tenant/workload/payload-tamper").unwrap();
        let mapper_name = volume_id.mapper_name();
        let mapper_path = format!("/dev/mapper/{mapper_name}");
        let _resources = PersistentResourcesOnDrop {
            mapper_name: mapper_name.clone(),
            mount_point: mount_point.to_string(),
        };
        let key = b"persistent-payload-tamper-test-key";
        let formatter = Luks2Formatter::default().with_integrity(true);

        persistent_parameters()
            .do_mount_persistent(
                device.dev_path(),
                mount_point,
                Zeroizing::new(key.to_vec()),
                volume_id.clone(),
            )
            .await
            .unwrap();
        nix::mount::umount(mount_point).unwrap();
        formatter.close_device(&mapper_name).unwrap();

        // LUKS2 integrity metadata is at the start of the payload area. Alter a
        // complete sector well inside the remaining physical payload, then
        // prove a fresh mapping cannot read through the corrupted data/tag.
        let corruption_offset = PERSISTENT_DATA_OFFSET_BYTES + 64 * 1024 * 1024;
        let device_file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(device.dev_path())
            .unwrap();
        let mut corrupted_sector = [0u8; SECTOR_SIZE as usize];
        device_file
            .read_exact_at(&mut corrupted_sector, corruption_offset)
            .unwrap();
        for byte in &mut corrupted_sector {
            *byte ^= 0xff;
        }
        device_file
            .write_all_at(&corrupted_sector, corruption_offset)
            .unwrap();
        device_file.sync_all().unwrap();

        let source = open_persistent_device(device.dev_path()).unwrap();
        let auth_key = derive_persistent_auth_key(key, &volume_id).unwrap();
        let record = load_persistent_metadata(&source, &auth_key, &volume_id)
            .unwrap()
            .unwrap();
        let header = load_verified_header(&source, &record, &auth_key, &volume_id).unwrap();
        formatter
            .open_device(
                device.dev_path(),
                Some(header.path().to_str().unwrap()),
                &mapper_name,
                key,
            )
            .unwrap();

        let mut mapper = File::open(&mapper_path).unwrap();
        let mut buffer = vec![0u8; 1024 * 1024];
        let read_error = loop {
            match mapper.read(&mut buffer) {
                Ok(0) => panic!("dm-integrity accepted a corrupted persistent payload"),
                Ok(_) => {}
                Err(error) => break error,
            }
        };
        assert_eq!(read_error.raw_os_error(), Some(nix::libc::EIO));
    }

    #[cfg(target_os = "linux")]
    #[derive(Clone, Copy, Debug)]
    enum PersistentCrashBoundary {
        BeforeMetadata,
        AfterPreparedMetadata,
        AfterHeaderCommit,
        AfterMapperOpen,
        AfterFilesystemFormat,
        AfterFilesystemMount,
        AfterReadyMetadata,
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "requires root, cryptsetup, loop devices, mkfs, blkid, and mount privileges"]
    #[serial]
    async fn persistent_luks2_recovers_across_initialization_phase_boundaries() {
        for (index, boundary) in [
            PersistentCrashBoundary::BeforeMetadata,
            PersistentCrashBoundary::AfterPreparedMetadata,
            PersistentCrashBoundary::AfterHeaderCommit,
            PersistentCrashBoundary::AfterMapperOpen,
            PersistentCrashBoundary::AfterFilesystemFormat,
            PersistentCrashBoundary::AfterFilesystemMount,
            PersistentCrashBoundary::AfterReadyMetadata,
        ]
        .into_iter()
        .enumerate()
        {
            let device = TempFileLoopDevice::new(128 * 1024 * 1024).unwrap();
            let mount_directory = tempfile::tempdir().unwrap();
            let mount_point = mount_directory.path().to_str().unwrap();
            let volume_id =
                PersistentVolumeId::try_from(format!("tenant/workload/crash-{index}").as_str())
                    .unwrap();
            let mapper_name = volume_id.mapper_name();
            let mapper_path = format!("/dev/mapper/{mapper_name}");
            let _resources = PersistentResourcesOnDrop {
                mapper_name: mapper_name.clone(),
                mount_point: mount_point.to_string(),
            };
            let key = b"persistent-crash-boundary-test-key";
            let formatter = Luks2Formatter::default().with_integrity(true);
            let mut expect_sentinel = false;

            if matches!(boundary, PersistentCrashBoundary::AfterReadyMetadata) {
                persistent_parameters()
                    .do_mount_persistent(
                        device.dev_path(),
                        mount_point,
                        Zeroizing::new(key.to_vec()),
                        volume_id.clone(),
                    )
                    .await
                    .unwrap();
                std::fs::write(mount_directory.path().join("sentinel"), b"preserve me").unwrap();
                expect_sentinel = true;
                nix::mount::umount(mount_point).unwrap();
                formatter.close_device(&mapper_name).unwrap();
            } else if !matches!(boundary, PersistentCrashBoundary::BeforeMetadata) {
                let device_file = open_persistent_device(device.dev_path()).unwrap();
                let auth_key = derive_persistent_auth_key(key, &volume_id).unwrap();
                let prepared = PersistentMetadataRecord::prepared(&volume_id);
                store_persistent_metadata(&device_file, &prepared, &auth_key).unwrap();

                if !matches!(boundary, PersistentCrashBoundary::AfterPreparedMetadata) {
                    let (header, _) = initialize_persistent_header(
                        &formatter,
                        device.dev_path(),
                        &device_file,
                        &prepared,
                        &auth_key,
                        key,
                        &volume_id,
                    )
                    .unwrap();

                    if !matches!(boundary, PersistentCrashBoundary::AfterHeaderCommit) {
                        formatter
                            .open_device(
                                device.dev_path(),
                                Some(header.path().to_str().unwrap()),
                                &mapper_name,
                                key,
                            )
                            .unwrap();
                    }

                    if matches!(
                        boundary,
                        PersistentCrashBoundary::AfterFilesystemFormat
                            | PersistentCrashBoundary::AfterFilesystemMount
                    ) {
                        FsFormatter {
                            fs_type: FsType::Ext4,
                            force: true,
                            args: Vec::new(),
                        }
                        .format_with_eager_inode_initialization(&mapper_path)
                        .unwrap();
                    }
                    if matches!(boundary, PersistentCrashBoundary::AfterFilesystemMount) {
                        mount_filesystem(&mapper_path, mount_point, FsType::Ext4).unwrap();
                        std::fs::write(mount_directory.path().join("sentinel"), b"preserve me")
                            .unwrap();
                        expect_sentinel = true;
                    } else if matches!(boundary, PersistentCrashBoundary::AfterFilesystemFormat) {
                        formatter.close_device(&mapper_name).unwrap();
                    }
                }
            }

            persistent_parameters()
                .do_mount_persistent(
                    device.dev_path(),
                    mount_point,
                    Zeroizing::new(key.to_vec()),
                    volume_id.clone(),
                )
                .await
                .unwrap_or_else(|error| panic!("recovery from {boundary:?} failed: {error:#}"));

            assert_eq!(
                persistent_state(device.dev_path(), key, &volume_id),
                PersistentLuksState::Ready,
                "wrong state after recovering {boundary:?}"
            );
            if expect_sentinel {
                assert_eq!(
                    std::fs::read(mount_directory.path().join("sentinel")).unwrap(),
                    b"preserve me",
                    "filesystem was reformatted while recovering {boundary:?}"
                );
            }
        }
    }

    #[test]
    #[cfg_attr(target_arch = "s390x", ignore)]
    #[serial]
    fn encrypt_open_device_no_integrity() {
        let mut bin_file = tempfile::NamedTempFile::new().unwrap();

        bin_file
            .as_file_mut()
            .write_all(&vec![0; 20 * 1024 * 1024])
            .unwrap();
        let path = bin_file.path().to_str().unwrap();

        let passphrase = Zeroizing::new(TEST_PASSPHRASE.to_vec());
        let luks2_formatter = Luks2Formatter { integrity: false };
        luks2_formatter
            .encrypt_device(path, None, &passphrase)
            .unwrap();

        luks2_formatter
            .open_device(path, None, NAME, &passphrase)
            .unwrap();
        let _device_guard = CloseDeviceOnDrop(NAME.to_string());
    }

    #[test]
    #[cfg_attr(target_arch = "s390x", ignore)]
    #[serial]
    fn encrypt_open_device_integrity() {
        let mut bin_file = tempfile::NamedTempFile::new().unwrap();

        bin_file
            .as_file_mut()
            .write_all(&vec![0; 20 * 1024 * 1024])
            .unwrap();
        let path = bin_file.path().to_str().unwrap();

        let passphrase = Zeroizing::new(TEST_PASSPHRASE.to_vec());
        let luks2_formatter = Luks2Formatter { integrity: true };
        luks2_formatter
            .encrypt_device(path, None, &passphrase)
            .unwrap();

        luks2_formatter
            .open_device(path, None, NAME, &passphrase)
            .unwrap();
        let _device_guard = CloseDeviceOnDrop(NAME.to_string());
    }

    #[test]
    #[cfg_attr(target_arch = "s390x", ignore)]
    #[serial]
    fn encrypt_open_device_no_integrity_with_header() {
        let mut bin_file = tempfile::NamedTempFile::new().unwrap();
        bin_file
            .as_file_mut()
            .write_all(&vec![0; 20 * 1024 * 1024])
            .unwrap();
        let path = bin_file.path().to_str().unwrap();
        let header_path = luks_header_path(path);
        prepare_luks_header_file(&header_path).unwrap();
        let _guard = RemoveHeaderOnDrop(header_path.clone());

        let passphrase = Zeroizing::new(TEST_PASSPHRASE.to_vec());
        let luks2_formatter = Luks2Formatter { integrity: false };
        luks2_formatter
            .encrypt_device(path, Some(&header_path), &passphrase)
            .unwrap();

        luks2_formatter
            .open_device(path, Some(&header_path), NAME, &passphrase)
            .unwrap();
        let _device_guard = CloseDeviceOnDrop(NAME.to_string());
    }

    #[test]
    #[cfg_attr(target_arch = "s390x", ignore)]
    #[serial]
    fn encrypt_open_device_integrity_with_header() {
        let mut bin_file = tempfile::NamedTempFile::new().unwrap();
        bin_file
            .as_file_mut()
            .write_all(&vec![0; 20 * 1024 * 1024])
            .unwrap();
        let path = bin_file.path().to_str().unwrap();
        let header_path = luks_header_path(path);
        prepare_luks_header_file(&header_path).unwrap();
        let _guard = RemoveHeaderOnDrop(header_path.clone());

        let passphrase = Zeroizing::new(TEST_PASSPHRASE.to_vec());
        let luks2_formatter = Luks2Formatter { integrity: true };
        luks2_formatter
            .encrypt_device(path, Some(&header_path), &passphrase)
            .unwrap();

        luks2_formatter
            .open_device(path, Some(&header_path), NAME, &passphrase)
            .unwrap();
        let _device_guard = CloseDeviceOnDrop(NAME.to_string());
    }

    #[test]
    #[serial]
    fn encrypt_with_existing_header_file() {
        let mut bin_file = tempfile::NamedTempFile::new().unwrap();
        bin_file
            .as_file_mut()
            .write_all(&vec![0; 20 * 1024 * 1024])
            .unwrap();
        let path = bin_file.path().to_str().unwrap();
        let header_path = luks_header_path(path);
        prepare_luks_header_file(&header_path).unwrap();
        let _guard = RemoveHeaderOnDrop(header_path.clone());

        let passphrase = Zeroizing::new(TEST_PASSPHRASE.to_vec());
        let luks2_formatter = Luks2Formatter { integrity: false };
        let result = luks2_formatter.encrypt_device(path, Some(&header_path), &passphrase);
        assert!(result.is_ok());
    }

    #[test]
    #[serial]
    fn open_device_missing_header_file_fails() {
        let mut bin_file = tempfile::NamedTempFile::new().unwrap();
        bin_file
            .as_file_mut()
            .write_all(&vec![0; 20 * 1024 * 1024])
            .unwrap();
        let path = bin_file.path().to_str().unwrap();
        let header_path = luks_header_path(path);
        prepare_luks_header_file(&header_path).unwrap();
        let _guard = RemoveHeaderOnDrop(header_path.clone());

        let passphrase = Zeroizing::new(TEST_PASSPHRASE.to_vec());
        let luks2_formatter = Luks2Formatter { integrity: false };
        luks2_formatter
            .encrypt_device(path, Some(&header_path), &passphrase)
            .unwrap();

        std::fs::remove_file(&header_path).unwrap();

        let result =
            luks2_formatter.open_device(path, Some(header_path.as_str()), NAME, &passphrase);
        assert!(result.is_err());
    }

    #[test]
    fn prepare_luks_header_file_rejects_existing_path() {
        use rand::{distr::Alphanumeric, rng, RngExt};

        let path_str = format!(
            "/dev/{}",
            rng()
                .sample_iter(&Alphanumeric)
                .take(16)
                .map(char::from)
                .collect::<String>()
        );

        let header_path = luks_header_path(&path_str);
        prepare_luks_header_file(&header_path).unwrap();
        let result = prepare_luks_header_file(&header_path);

        match result {
            Err(err) => assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists),
            other => panic!("unexpected result: {other:?}"),
        }
        let _ = std::fs::remove_file(&header_path);
    }

    /// This test can be used to clean useless devices under /dev/mapper/
    #[ignore]
    #[test]
    fn create_encrypt_close_test() {
        let luks2_formatter = Luks2Formatter { integrity: false };
        luks2_formatter
            .close_device("d7920c40-e7dc-48a4-aff7-6eab51c7d2d5")
            .unwrap();
    }
}
