use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// The LayerStore abstracts the image layers storage on the file system.
#[derive(Clone, Default, Debug)]
pub struct LayerStore {
    /// OCI image layer data store dir.
    pub data_dir: PathBuf,

    /// Next layer index
    layers_index: Arc<AtomicUsize>,
}

impl LayerStore {
    /// Retrieves the next layer index by computing the maximum index from the
    /// existing layers in data dir.
    pub fn get_layer_index(data_dir: PathBuf) -> Result<AtomicUsize, anyhow::Error> {
        if !data_dir.exists() {
            return Ok(AtomicUsize::new(0));
        }
        let paths = fs::read_dir(data_dir)?;
        let mut next = 0;
        for path in paths {
            let entry_path = path?;
            // these should not fail since each file name must be an index.
            // If for some reason, file name is not an index it will not
            // cause any conflicts with new and existing layers.
            if let Some(name) = entry_path.file_name().to_str() {
                let n = name.parse::<usize>().unwrap_or(0);
                if n >= next {
                    next = n + 1;
                }
            }
        }
        Ok(AtomicUsize::new(next))
    }

    /// Construct an instance of `LayerStore` with specific work directory.
    pub fn new(work_dir: PathBuf) -> Result<Self, anyhow::Error> {
        let data_dir = work_dir.join("layers");
        Ok(Self {
            data_dir: data_dir.clone(),
            layers_index: Arc::new(Self::get_layer_index(data_dir)?),
        })
    }

    /// Returns the unique store path for a new layer
    pub fn new_layer_store_path(&self) -> PathBuf {
        let index = self.layers_index.fetch_add(1, Ordering::Relaxed);
        self.data_dir.join(index.to_string())
    }
}

#[cfg(test)]
mod tests {
    use crate::layer_store::LayerStore;

    use tokio::fs;

    #[tokio::test]
    async fn test_store_path_unique() {
        let tempdir = tempfile::tempdir().unwrap();
        let layer_store =
            LayerStore::new(tempdir.path().to_path_buf()).expect("create layer store failed");

        let layer1 = layer_store.new_layer_store_path(); // 0
        let layer2 = layer_store.new_layer_store_path(); // 1

        assert_ne!(layer1, layer2, "store paths are not unique");
        assert_eq!(layer1.file_name().unwrap(), "0", "path {:?}", layer1);
        assert_eq!(layer2.file_name().unwrap(), "1", "path {:?}", layer2);

        fs::create_dir_all(layer1.clone()).await.unwrap();
        fs::create_dir_all(layer2.clone()).await.unwrap();

        let layer_store =
            LayerStore::new(tempdir.path().to_path_buf()).expect("create layer store failed");

        let layer3 = layer_store.new_layer_store_path(); // 2

        fs::create_dir_all(layer3.clone()).await.unwrap();

        assert_ne!(layer1, layer3, "store paths are not unique");

        assert_ne!(layer2, layer3, "store paths are not unique");

        assert_eq!(layer3.file_name().unwrap(), "2", "path {:?}", layer3);

        let layer_store1 = layer_store.clone();

        let layer4 = layer_store.new_layer_store_path(); // 3
        let layer5 = layer_store1.new_layer_store_path(); // 4

        fs::create_dir_all(layer4.clone()).await.unwrap();
        fs::create_dir_all(layer5.clone()).await.unwrap();

        assert_ne!(layer4, layer5, "store paths are not unique");
        assert_eq!(layer4.file_name().unwrap(), "3", "path {:?}", layer4);
        assert_eq!(layer5.file_name().unwrap(), "4", "path {:?}", layer5);
    }
}
