// Copyright (c) 2021 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::*;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;

use crate::kbc_modules::{KbcCheckInfo, KbcInstance, KBC_MODULE_LIST};

lazy_static! {
    pub static ref KBC_RUNTIME: Arc<Mutex<KbcRuntime>> = Arc::new(Mutex::new(KbcRuntime::new()));
}

pub struct KbcRuntime {
    kbc_instance_map: HashMap<String, KbcInstance>,
}

impl KbcRuntime {
    fn new() -> KbcRuntime {
        KbcRuntime {
            kbc_instance_map: HashMap::new(),
        }
    }

    fn register_instance(&mut self, kbc_name: String, kbc_instance: KbcInstance) {
        self.kbc_instance_map.insert(kbc_name, kbc_instance);
    }

    fn instantiate_kbc(&mut self, kbc_name: String, kbs_uri: String) -> Result<()> {
        let kbc_module_list = KBC_MODULE_LIST.clone();
        let instantiate_func = kbc_module_list.get_func(&kbc_name)?;
        let kbc_instance = (instantiate_func)(kbs_uri);
        self.register_instance(kbc_name, kbc_instance);
        Ok(())
    }

    pub fn decrypt(
        &mut self,
        kbc_name: String,
        kbs_uri: String,
        annotation: String,
    ) -> Result<Vec<u8>> {
        if self.kbc_instance_map.get_mut(&kbc_name).is_none() {
            self.instantiate_kbc(kbc_name.clone(), kbs_uri)?;
        }
        let kbc_instance = self
            .kbc_instance_map
            .get_mut(&kbc_name)
            .ok_or(anyhow!("KBC runtime: The KBC instance does not existing!"))?;
        let plain_payload = kbc_instance.decrypt_payload(&annotation)?;
        Ok(plain_payload)
    }

    pub fn check(&self, kbc_name: String) -> Result<KbcCheckInfo> {
        let kbc_instance = self
            .kbc_instance_map
            .get(&kbc_name)
            .ok_or(anyhow!("KBC runtime: The KBC instance does not existing!"))?;
        let check_info: KbcCheckInfo = kbc_instance.check()?;
        Ok(check_info)
    }
}
