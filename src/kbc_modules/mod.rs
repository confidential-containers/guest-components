// Copyright (c) 2021 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

// Add your specific kbc declaration here.
// For example: "pub mod sample_kbc;"
#[cfg(feature = "eaa_kbc")]
pub mod eaa_kbc;
#[cfg(feature = "offline_fs_kbc")]
pub mod offline_fs_kbc;
#[cfg(feature = "sample_kbc")]
pub mod sample_kbc;

use anyhow::*;
use std::collections::HashMap;
use std::sync::Arc;

// KbcInterface is a standard interface that all KBC modules need to implement.
pub trait KbcInterface {
    fn check(&self) -> Result<KbcCheckInfo>;
    fn decrypt_payload(&mut self, annotation: &str) -> Result<Vec<u8>>;
}

pub type KbcInstance = Box<dyn KbcInterface + Sync + Send>;
type KbcInstantiateFunc = Box<dyn Fn(String) -> KbcInstance + Send + Sync>;

// KbcCheckInfo is used by KBC module instances to report their internal status to AA.
pub struct KbcCheckInfo {
    pub kbs_info: HashMap<String, String>,
    // In the future, more KBC status fields will be expanded here.
}

lazy_static! {
    pub static ref KBC_MODULE_LIST: Arc<KbcModuleList> = Arc::new(KbcModuleList::new());
}

pub struct KbcModuleList {
    mod_list: HashMap<String, KbcInstantiateFunc>,
}

impl KbcModuleList {
    fn new() -> KbcModuleList {
        let mut mod_list = HashMap::new();

        #[cfg(feature = "sample_kbc")]
        {
            let instantiate_func: KbcInstantiateFunc = Box::new(|kbs_uri: String| -> KbcInstance {
                Box::new(sample_kbc::SampleKbc::new(kbs_uri))
            });
            mod_list.insert("sample_kbc".to_string(), instantiate_func);
        }

        #[cfg(feature = "offline_fs_kbc")]
        {
            let instantiate_func: KbcInstantiateFunc = Box::new(|_: String| -> KbcInstance {
                Box::new(offline_fs_kbc::OfflineFsKbc::new())
            });
            mod_list.insert("offline_fs_kbc".to_string(), instantiate_func);
        }

        #[cfg(feature = "eaa_kbc")]
        {
            let instantiate_func: KbcInstantiateFunc = Box::new(|kbs_uri: String| -> KbcInstance {
                Box::new(eaa_kbc::EAAKbc::new(kbs_uri))
            });
            mod_list.insert("eaa_kbc".to_string(), instantiate_func);
        }

        KbcModuleList { mod_list: mod_list }
    }

    pub fn get_func(&self, kbc_name: &str) -> Result<&KbcInstantiateFunc> {
        let instantiate_func: &KbcInstantiateFunc = self
            .mod_list
            .get(kbc_name)
            .ok_or(anyhow!("AA does not support the given KBC module!"))?;
        Ok(instantiate_func)
    }
}
