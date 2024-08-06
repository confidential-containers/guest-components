use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;
use std::path::Path;

use crate::image::{ImageMeta, LayerMeta};

pub const METAFILE: &str = "meta_store.json";

/// `image-rs` container metadata storage database.
#[derive(Clone, Default, Serialize, Deserialize, Debug)]
pub struct MetaStore {
    // image_db holds map of image ID with image data.
    pub image_db: HashMap<String, ImageMeta>,

    // layer_db holds map of layer digest with layer meta.
    pub layer_db: HashMap<String, LayerMeta>,

    // snapshot_db holds map of snapshot with work dir index.
    pub snapshot_db: HashMap<String, usize>,
}

impl TryFrom<&Path> for MetaStore {
    /// load `MetaStore` from a local file
    type Error = anyhow::Error;
    fn try_from(path: &Path) -> Result<Self, Self::Error> {
        let file = File::open(path)
            .map_err(|e| anyhow!("failed to open metastore file {}", e.to_string()))?;
        serde_json::from_reader::<File, MetaStore>(file)
            .map_err(|e| anyhow!("failed to parse metastore file {}", e.to_string()))
    }
}

impl MetaStore {
    pub fn write_to_file(&self, path: &str) -> Result<()> {
        let file = File::create(path)
            .map_err(|e| anyhow!("failed to create metastore file: {}", e.to_string()))?;
        serde_json::to_writer(file, &self)
            .map_err(|e| anyhow!("failed to write metastore to file: {}", e.to_string()))
    }
}
