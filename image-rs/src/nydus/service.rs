// Copyright (c) 2023. Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, bail, Result};
use log::{error, info};
use nix::mount::MsFlags;
use oci_client::Reference;
use oci_spec::image::Os;
use std::convert::TryInto;
use std::path::Path;
use std::{fs, thread};

use tokio::task;

use nydus_api::{BlobCacheEntry, BuildTimeInfo};
use nydus_service::daemon::DaemonController;
use nydus_service::{
    create_daemon, create_fuse_daemon, create_vfs_backend, FsBackendMountCmd, FsBackendType,
};

use super::utils::get_build_time_info;
use crate::bundle::{create_runtime_config, BUNDLE_ROOTFS};
use crate::config::{FscacheConfig, FuseConfig, NydusConfig};
use crate::image::ImageMeta;
use crate::snapshots::Snapshotter;

pub const NYDUS_ROOTFS: &str = "nydus_rootfs";

lazy_static::lazy_static! {
    static ref DAEMON_CONTROLLER: DaemonController = DaemonController::default();
    static ref BTI: BuildTimeInfo = get_build_time_info();
}

pub async fn start_nydus_service(
    image_data: &ImageMeta,
    reference: Reference,
    nydus_config: &NydusConfig,
    work_dir: &Path,
    bundle_dir: &Path,
    snapshot: &mut Box<dyn Snapshotter>,
) -> Result<String> {
    // when using nydus image, layer_metas containes only bootstrap layer meta
    let bootstrap_meta = image_data.layer_metas[0].clone();
    let bootstrap = Path::new(&bootstrap_meta.store_path)
        .join("image")
        .join("image.boot");
    let mountpoint = bundle_dir.join(NYDUS_ROOTFS);
    let id = nydus_config.id.clone();
    let work_dir_buf = work_dir.to_owned();

    if nydus_config.is_fuse() {
        let fuse_config = nydus_config
            .get_fuse_config()
            .expect("Fuse configuration not found")
            .clone();
        if let Err(e) = task::spawn_blocking(move || {
            process_fuse_daemon(
                id,
                reference,
                &work_dir_buf,
                &bootstrap,
                &mountpoint,
                &fuse_config,
            )
        })
        .await
        {
            bail!("Failed to start nydus service, {:?}", e);
        };
    } else if nydus_config.is_fscache() {
        let fscache_config = nydus_config
            .get_fscache_config()
            .expect("Fscache configuration not found")
            .clone();
        let blob_id = if bootstrap_meta.compressed_digest.starts_with("sha256:") {
            bootstrap_meta
                .compressed_digest
                .strip_prefix("sha256:")
                .unwrap()
                .to_owned()
        } else if bootstrap_meta.compressed_digest.starts_with("sha512:") {
            bootstrap_meta
                .compressed_digest
                .strip_prefix("sha512:")
                .unwrap()
                .to_owned()
        } else {
            bootstrap_meta.compressed_digest.clone()
        };

        if let Err(e) = task::spawn_blocking(move || {
            process_fscache_daemon(
                id,
                reference,
                &blob_id,
                &work_dir_buf,
                &bootstrap,
                &mountpoint,
                &fscache_config,
            )
        })
        .await
        {
            bail!("Failed to start nydus service, {:?}", e);
        };
    } else {
        bail!("Only fuse and fscache fs drivers are supported right now");
    };

    thread::spawn(move || {
        let daemon = DAEMON_CONTROLLER.get_daemon();
        if let Some(fs) = daemon.get_default_fs_service() {
            DAEMON_CONTROLLER.set_fs_service(fs);
        }

        // Run the main event loop
        if DAEMON_CONTROLLER.is_active() {
            DAEMON_CONTROLLER.run_loop();
        }

        // Gracefully shutdown system.
        info!("nydusd quits");
        DAEMON_CONTROLLER.set_singleton_mode(false);
        DAEMON_CONTROLLER.shutdown();
    });
    let image_id = create_nydus_bundle(image_data, bundle_dir, snapshot)?;

    Ok(image_id)
}

#[allow(clippy::too_many_arguments)]
pub fn process_fuse_daemon(
    id: Option<String>,
    reference: Reference,
    work_dir: &Path,
    bootstrap: &Path,
    mountpoint: &Path,
    fuse_config: &FuseConfig,
) -> Result<()> {
    let config = format!(
        r###"
{{
    "device": {{
        "backend": {{
            "type": "registry",
            "config": {{
                "scheme": "https",
                "host": {:?},
                "repo": {:?}
            }}
        }},
        "cache": {{
            "type": "blobcache",
            "config": {{
                "compressed": false,
                "work_dir": {:?}
            }}
        }}
    }},
    "mode": "direct",
    "digest_validate": false,
    "iostats_files": false
}}
"###,
        reference.registry(),
        reference.repository(),
        work_dir.join("cache"),
    );

    if !mountpoint.exists() {
        std::fs::create_dir_all(mountpoint)?;
    }

    if !work_dir.join("cache").exists() {
        std::fs::create_dir_all(work_dir.join("cache"))?;
    }

    let virtual_mnt = match &fuse_config.virtual_mountpoint {
        Some(mnt) => String::from(mnt.to_string_lossy()),
        None => String::from("/"),
    };
    let cmd = FsBackendMountCmd {
        fs_type: FsBackendType::Rafs,
        source: String::from(bootstrap.to_string_lossy()),
        config,
        mountpoint: virtual_mnt,
        prefetch_files: fuse_config.prefetch_files.clone(),
    };
    let vfs = create_vfs_backend(FsBackendType::Rafs, true, false)?;
    let p = (&fuse_config.fail_over_policy)
        .try_into()
        .inspect_err(|_| {
            error!("Invalid failover policy");
        })?;

    let daemon = {
        create_fuse_daemon(
            mountpoint.to_str().unwrap(),
            vfs,
            None,
            id,
            fuse_config.fuse_threads,
            DAEMON_CONTROLLER.alloc_waker(),
            Some("api_sock"),
            false,
            true,
            p,
            Some(cmd),
            BTI.to_owned(),
        )
        .inspect(|_| {
            info!("Fuse daemon started!");
        })
        .map_err(|e| {
            error!("Failed in starting fuse daemon: {}", e);
            e
        })?
    };

    DAEMON_CONTROLLER.set_daemon(daemon);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn process_fscache_daemon(
    id: Option<String>,
    reference: Reference,
    blob_id: &str,
    work_dir: &Path,
    bootstrap: &Path,
    mountpoint: &Path,
    fscache_config: &FscacheConfig,
) -> Result<()> {
    // All images from the same registry share the same domain.
    let domain_id = reference.registry();
    let config_json = format!(
        r###"
{{
    "type": "bootstrap",
    "id": {:?},
    "domain_id": {:?},
    "config_v2": {{
        "version": 2,
        "backend": {{
            "type": "registry",
            "registry": {{
                "scheme": "https",
                "host": {:?},
                "repo": {:?}
            }}
        }},
        "cache": {{
            "type": "fscache",
            "fscache": {{
                "work_dir": {:?}
            }}
        }},
        "metadata_path": {:?}
    }}
}}
"###,
        blob_id,
        domain_id,
        reference.registry(),
        reference.repository(),
        &work_dir.join("cache"),
        bootstrap,
    );

    if !mountpoint.exists() {
        std::fs::create_dir_all(mountpoint)?;
    }

    if !work_dir.join("cache").exists() {
        std::fs::create_dir_all(work_dir.join("cache"))?;
    }

    let config: serde_json::Value =
        serde_json::from_str(&config_json).map_err(|_e| anyhow!("invalid configuration file"))?;
    let mut conf: Box<BlobCacheEntry> =
        serde_json::from_str(&config_json).map_err(|_e| anyhow!("invalid configuration file"))?;
    if !conf.prepare_configuration_info() {
        bail!("Failed to prepare blob entry configuration info");
    }

    let fscache = match fscache_config.fscache.clone() {
        None => work_dir.join("cache"),
        Some(f) => f,
    };
    if !fscache.exists() {
        std::fs::create_dir_all(&fscache)?;
    }

    let tag = fscache_config.fscache_tag.as_deref();
    let threads = fscache_config.fscache_threads.to_string();
    let daemon = create_daemon(
        id,
        None,
        fscache.to_str(),
        tag,
        Some(threads.as_str()),
        Some(config),
        BTI.to_owned(),
        DAEMON_CONTROLLER.alloc_waker(),
    )
    .map_err(|e| {
        error!("Failed to start fscache daemon: {}", e);
        e
    })?;
    info!("Start nydus fscache daemon.");

    DAEMON_CONTROLLER.set_singleton_mode(true);
    if let Some(blob_mgr) = daemon.get_blob_cache_mgr() {
        if let Err(e) = blob_mgr.add_blob_entry(&conf) {
            bail!("Failed to add blob entry to blob cache mgr {}", e);
        }
        DAEMON_CONTROLLER.set_blob_cache_mgr(blob_mgr);
    }

    DAEMON_CONTROLLER.set_daemon(daemon);
    if let Err(e) = erofs_mount(domain_id, blob_id, mountpoint) {
        bail!("Failed to mount {}", e);
    }

    Ok(())
}

pub fn create_nydus_bundle(
    image_data: &ImageMeta,
    bundle_dir: &Path,
    snapshot: &mut Box<dyn Snapshotter>,
) -> Result<String> {
    let image_config = image_data.image_config.clone();
    if image_config.os() != &Os::Linux {
        bail!("unsupport OS image {:?}", image_config.os());
    }

    let nydus_rootfs = &bundle_dir.join(NYDUS_ROOTFS);
    snapshot.mount(
        &[&nydus_rootfs.to_string_lossy()],
        &bundle_dir.join(BUNDLE_ROOTFS),
    )?;

    create_runtime_config(&image_config, bundle_dir)?;
    let image_id = image_data.id.clone();
    Ok(image_id)
}

pub fn erofs_mount(domain_id: &str, fscache_id: &str, mount_path: &Path) -> Result<()> {
    if !mount_path.exists() {
        fs::create_dir_all(mount_path)?;
    }

    let flags = MsFlags::empty();
    let options = if !domain_id.is_empty() && domain_id != fscache_id {
        format!("domain_id={},fsid={}", domain_id, fscache_id)
    } else {
        format!("fsid={}", fscache_id)
    };

    nix::mount::mount(
        Some("erofs"),
        mount_path,
        Some("erofs"),
        flags,
        Some(options.as_str()),
    )
    .map_err(|e| {
        anyhow!(
            "failed to mount erofs to {:?}, with error: {}. 
                If using this erofs feature, make sure your Linux kernel version >= 6.1",
            mount_path,
            e
        )
    })?;

    Ok(())
}

pub fn erofs_unmount(mount_point: &Path) -> Result<()> {
    nix::mount::umount(mount_point)?;

    Ok(())
}
