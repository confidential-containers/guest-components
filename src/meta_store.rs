use serde::Deserialize;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::fs::File;
use std::path::{Path, PathBuf};
use thiserror::Error;

use crate::image::{ImageMeta, LayerMeta};

pub const METAFILE: &str = "meta_store.json";

#[derive(Error, Debug)]
pub enum MetaStoreError {
    #[error("failed to open metastore file {0}: {1}")]
    FileOpenFail(PathBuf, std::io::Error),

    #[error("failed to open metastore file {0}: {1}")]
    FileParseFail(PathBuf, serde_json::Error),
}

pub type Result<T> = std::result::Result<T, MetaStoreError>;

/// `image-rs` container metadata storage database.
#[derive(Clone, Default, Deserialize, Debug)]
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
    type Error = MetaStoreError;

    fn try_from(path: &Path) -> Result<Self> {
        let file =
            File::open(path).map_err(|e| MetaStoreError::FileOpenFail(path.to_path_buf(), e))?;

        serde_json::from_reader::<File, MetaStore>(file)
            .map_err(|e| MetaStoreError::FileParseFail(path.to_path_buf(), e))
    }
}
