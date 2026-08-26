// Copyright (c) 2026 NVIDIA Corporation
//
// SPDX-License-Identifier: Apache-2.0

//! Manifest-driven secure block-volume activation.

use std::collections::HashMap;

use anyhow::anyhow;
use resource_uri::{ResourcePluginPath, ResourceUri, DEFAULT_RESOURCE_PLUGIN};
use serde::Deserialize;
use tokio::sync::Mutex;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::storage::{
    drivers::luks2::{
        activate_persistent_ext4, Luks2Formatter, PersistentActivation, PersistentVolumeId,
    },
    volume_type::blockdevice::{get_device_path, parse_device_id},
};

const MAX_MANIFEST_SIZE: usize = 64 * 1024;
const SUPPORTED_SCHEMA_VERSION: u32 = 1;
const SUPPORTED_PROTECTION_TYPE: &str = "luks2-integrity-rw";

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("secure-volume manifest exceeds {MAX_MANIFEST_SIZE} bytes")]
    ManifestTooLarge,

    #[error("failed to parse secure-volume manifest: {0}")]
    ManifestParse(#[from] serde_json::Error),

    #[error("invalid secure-volume manifest: {0}")]
    InvalidManifest(String),

    #[error("invalid secure-volume device: {0}")]
    InvalidDevice(String),

    #[error("requested access {requested} does not match manifest access {manifest}")]
    AccessMismatch {
        requested: VolumeAccess,
        manifest: VolumeAccess,
    },

    #[error("secure-volume access {0} is not supported")]
    UnsupportedAccess(VolumeAccess),

    #[error("secure-volume device {0} already has an activation")]
    DuplicateDevice(String),

    #[error("secure volume {0} already has an activation")]
    DuplicateVolume(String),

    #[error("secure-volume activation failed: {0:#}")]
    Activation(#[source] anyhow::Error),
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum VolumeAccess {
    ReadOnly,
    ReadWrite,
}

impl std::fmt::Display for VolumeAccess {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::ReadOnly => "readOnly",
            Self::ReadWrite => "readWrite",
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Manifest {
    pub schema_version: u32,
    pub volume_id: String,
    pub volume_version: String,
    pub device_size_bytes: u64,
    pub access: VolumeAccess,
    pub protection: Protection,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Protection {
    #[serde(rename = "type")]
    pub protection_type: String,
    pub key_uri: String,
    pub luks_uuid: String,
}

impl Manifest {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_MANIFEST_SIZE {
            return Err(Error::ManifestTooLarge);
        }

        let manifest: Self = serde_json::from_slice(bytes)?;
        manifest.validate()?;
        Ok(manifest)
    }

    fn validate(&self) -> Result<()> {
        if self.schema_version != SUPPORTED_SCHEMA_VERSION {
            return Err(Error::InvalidManifest(format!(
                "unsupported schemaVersion {}",
                self.schema_version
            )));
        }
        PersistentVolumeId::try_from(self.volume_id.as_str())
            .map_err(|error| Error::InvalidManifest(error.to_string()))?;
        validate_identifier("volumeVersion", &self.volume_version)?;
        if self.device_size_bytes == 0 || !self.device_size_bytes.is_multiple_of(4096) {
            return Err(Error::InvalidManifest(
                "deviceSizeBytes must be a nonzero multiple of 4096".to_string(),
            ));
        }

        if self.protection.protection_type != SUPPORTED_PROTECTION_TYPE {
            return Err(Error::InvalidManifest(format!(
                "unsupported protection type {}",
                self.protection.protection_type
            )));
        }
        validate_kbs_resource_uri(&self.protection.key_uri)?;

        let uuid = Uuid::parse_str(&self.protection.luks_uuid)
            .map_err(|error| Error::InvalidManifest(format!("invalid LUKS UUID: {error}")))?;
        if uuid.to_string() != self.protection.luks_uuid {
            return Err(Error::InvalidManifest(
                "luksUuid must use canonical lowercase UUID notation".to_string(),
            ));
        }
        Ok(())
    }

    pub fn validate_manifest_uri(&self, uri: &str) -> Result<()> {
        let path = validate_kbs_resource_uri(uri)?;
        if path.tag != self.volume_version {
            return Err(Error::InvalidManifest(
                "manifest resource tag must equal volumeVersion".to_string(),
            ));
        }
        Ok(())
    }

    pub fn ensure_access(&self, requested: VolumeAccess) -> Result<()> {
        if requested != self.access {
            return Err(Error::AccessMismatch {
                requested,
                manifest: self.access,
            });
        }
        if requested != VolumeAccess::ReadWrite {
            return Err(Error::UnsupportedAccess(requested));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Activation {
    pub activation_id: String,
    pub device_path: String,
    pub effective_access: VolumeAccess,
}

#[derive(Clone, Debug)]
struct ActivationState {
    device_id: String,
    volume_id: String,
    mapper_name: Option<String>,
}

#[derive(Default)]
struct Registry {
    activations: HashMap<String, ActivationState>,
}

impl Registry {
    fn reserve(
        &mut self,
        activation_id: String,
        device_id: String,
        volume_id: String,
    ) -> Result<()> {
        if self
            .activations
            .values()
            .any(|activation| activation.device_id == device_id)
        {
            return Err(Error::DuplicateDevice(device_id));
        }
        if self
            .activations
            .values()
            .any(|activation| activation.volume_id == volume_id)
        {
            return Err(Error::DuplicateVolume(volume_id));
        }
        self.activations.insert(
            activation_id,
            ActivationState {
                device_id,
                volume_id,
                mapper_name: None,
            },
        );
        Ok(())
    }
}

#[derive(Default)]
pub struct Manager {
    registry: Mutex<Registry>,
}

impl Manager {
    pub async fn activate(
        &self,
        device_id: &str,
        manifest: &Manifest,
        requested_access: VolumeAccess,
        key: Zeroizing<Vec<u8>>,
    ) -> Result<Activation> {
        manifest.ensure_access(requested_access)?;

        let (major, minor) = parse_device_id(device_id)
            .map_err(|error| Error::InvalidDevice(format!("invalid device ID: {error}")))?;
        let device_id = format!("{major}:{minor}");
        let device_path = get_device_path(major, minor).await.map_err(|error| {
            Error::InvalidDevice(format!("cannot resolve {device_id}: {error}"))
        })?;
        let volume_id = PersistentVolumeId::try_from(manifest.volume_id.as_str())
            .map_err(|error| Error::InvalidManifest(error.to_string()))?;
        let activation_id = Uuid::new_v4().to_string();

        self.registry.lock().await.reserve(
            activation_id.clone(),
            device_id,
            manifest.volume_id.clone(),
        )?;

        let result = self
            .activate_reserved(
                &device_path,
                volume_id,
                &manifest.protection.luks_uuid,
                manifest.device_size_bytes,
                key,
            )
            .await;

        match result {
            Ok(mapping) => {
                let mut registry = self.registry.lock().await;
                let Some(state) = registry.activations.get_mut(&activation_id) else {
                    let _ = Luks2Formatter::default().close_device(&mapping.mapper_name);
                    return Err(Error::Activation(anyhow!(
                        "secure-volume activation reservation disappeared"
                    )));
                };
                state.mapper_name = Some(mapping.mapper_name);
                drop(registry);
                Ok(Activation {
                    activation_id,
                    device_path: mapping.device_path,
                    effective_access: VolumeAccess::ReadWrite,
                })
            }
            Err(error) => {
                self.registry
                    .lock()
                    .await
                    .activations
                    .remove(&activation_id);
                Err(error)
            }
        }
    }

    async fn activate_reserved(
        &self,
        device_path: &str,
        volume_id: PersistentVolumeId,
        luks_uuid: &str,
        expected_size_bytes: u64,
        key: Zeroizing<Vec<u8>>,
    ) -> Result<PersistentActivation> {
        activate_persistent_ext4(device_path, key, volume_id, luks_uuid, expected_size_bytes)
            .await
            .map_err(Error::Activation)
    }

    /// Deactivation is idempotent. An unknown handle has no resources to release.
    pub async fn deactivate(&self, activation_id: &str) -> Result<()> {
        let mut registry = self.registry.lock().await;
        let Some(state) = registry.activations.get(activation_id) else {
            return Ok(());
        };
        let Some(mapper_name) = state.mapper_name.as_deref() else {
            return Err(Error::Activation(anyhow!(
                "secure-volume activation is still in progress"
            )));
        };

        Luks2Formatter::default()
            .close_device(mapper_name)
            .map_err(Error::Activation)?;
        registry.activations.remove(activation_id);
        Ok(())
    }
}

pub(crate) fn validate_kbs_resource_uri(uri: &str) -> Result<ResourcePluginPath> {
    let resource = ResourceUri::try_from(uri)
        .map_err(|error| Error::InvalidManifest(format!("invalid KBS resource URI: {error}")))?;
    if resource.plugin() != DEFAULT_RESOURCE_PLUGIN
        || !resource.kbs_address.is_empty()
        || resource.query.is_some()
        || resource.whole_uri() != uri
    {
        return Err(Error::InvalidManifest(
            "resource URI must be a canonical local, query-free kbs resource URI".to_string(),
        ));
    }
    ResourcePluginPath::try_from(resource)
        .map_err(|error| Error::InvalidManifest(error.to_string()))
}

fn validate_identifier(field: &str, value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(Error::InvalidManifest(format!(
            "{field} must be bounded canonical ASCII"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const MANIFEST_URI: &str = "kbs:///tenant/storage-manifests/volume-1-v1";

    fn valid_manifest() -> Vec<u8> {
        br#"{
          "schemaVersion": 1,
          "volumeId": "tenant/workload/volume-1",
          "volumeVersion": "volume-1-v1",
          "deviceSizeBytes": 1073741824,
          "access": "readWrite",
          "protection": {
            "type": "luks2-integrity-rw",
            "keyUri": "kbs:///tenant/storage-keys/volume-1-v1",
            "luksUuid": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
          }
        }"#
        .to_vec()
    }

    #[test]
    fn parses_supported_manifest_and_binds_resource_tag() {
        let manifest = Manifest::parse(&valid_manifest()).unwrap();
        manifest.validate_manifest_uri(MANIFEST_URI).unwrap();
        manifest.ensure_access(VolumeAccess::ReadWrite).unwrap();
    }

    #[test]
    fn rejects_unknown_manifest_fields() {
        let bytes = String::from_utf8(valid_manifest()).unwrap().replace(
            "\"volumeId\": \"tenant/workload/volume-1\",",
            "\"volumeId\": \"tenant/workload/volume-1\", \"mountPoint\": \"/data\",",
        );
        assert!(matches!(
            Manifest::parse(bytes.as_bytes()),
            Err(Error::ManifestParse(_))
        ));
    }

    #[test]
    fn rejects_unsupported_profile() {
        let bytes = String::from_utf8(valid_manifest())
            .unwrap()
            .replace("luks2-integrity-rw", "luks2-rw");
        assert!(matches!(
            Manifest::parse(bytes.as_bytes()),
            Err(Error::InvalidManifest(_))
        ));
    }

    #[test]
    fn rejects_unaligned_device_size() {
        let bytes = String::from_utf8(valid_manifest())
            .unwrap()
            .replace("1073741824", "1073741823");
        assert!(matches!(
            Manifest::parse(bytes.as_bytes()),
            Err(Error::InvalidManifest(_))
        ));
    }

    #[test]
    fn rejects_noncanonical_luks_uuid() {
        let bytes = String::from_utf8(valid_manifest()).unwrap().replace(
            "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
            "AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE",
        );
        assert!(matches!(
            Manifest::parse(bytes.as_bytes()),
            Err(Error::InvalidManifest(_))
        ));
    }

    #[test]
    fn rejects_manifest_alias_and_access_mismatch() {
        let manifest = Manifest::parse(&valid_manifest()).unwrap();
        assert!(manifest
            .validate_manifest_uri("kbs:///tenant/storage-manifests/latest")
            .is_err());
        assert!(matches!(
            manifest.ensure_access(VolumeAccess::ReadOnly),
            Err(Error::AccessMismatch { .. })
        ));
        assert!(validate_kbs_resource_uri(
            "kbs://untrusted.example/tenant/storage-manifests/volume-1-v1"
        )
        .is_err());
    }

    #[tokio::test]
    async fn deactivation_is_idempotent_for_unknown_handles() {
        let manager = Manager::default();
        manager.deactivate("already-released").await.unwrap();
        manager.deactivate("already-released").await.unwrap();
    }

    #[test]
    fn registry_rejects_duplicate_device_and_volume() {
        let mut registry = Registry::default();
        registry
            .reserve("one".into(), "8:0".into(), "tenant/volume-one".into())
            .unwrap();
        assert!(matches!(
            registry.reserve("two".into(), "8:0".into(), "tenant/volume-two".into()),
            Err(Error::DuplicateDevice(_))
        ));
        assert!(matches!(
            registry.reserve("three".into(), "8:1".into(), "tenant/volume-one".into()),
            Err(Error::DuplicateVolume(_))
        ));
    }
}
