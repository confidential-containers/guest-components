# KBC Module Development Guide

This guide will teach you how to develop a KBC module and integrate it into the source code of the AA according to the KBC module standard interface and integration mode. Please refer to [IMPLEMENTATION.md](IMPLEMENTATION.md)  for the  details of KBC module framework.

Now let's start.

## Development

First, create a new  KBC module (e.g, my_kbc) as following:

```
cd attestation-agent/kbc
mkdir my_kbc
cd my_kbc
touch mod.rs
```

Then, you need to import the definition of KBC module standard interface in mod.rs, that is, add the following codes in mod.rs:

```rust
use crate::kbc_modules::{KbcCheckInfo, KbcInterface};
```

Add the implementations for my_kbc module.

```rust
// kbc/my_kbc/mod.rs

pub struct MyKbc {
    // The object of this structure will exist as a KBC instance
    ... ...
}

impl KbcInterface for MyKbc {
    // Check interface: 
    // used to let the KBC runtime obtain the KBS information of the current KBC instance
    // The KbcCheckInfo structure is defined as follows:
    // pub struct KbcCheckInfo {
    //     pub kbs_info: HashMap<String, String>,
    // }
    fn check(&self) -> KbcCheckInfo {...}
  
    // decrypt_payload interface: 
    // used to parse layer annotation and decrypt PLBCO
    // Input parameter: layer annotation
    // Return value: decrypted PLBCO
    fn decrypt_payload(&mut self, annotation: &str) -> Result<Vec<u8>> {...}
}

impl MyKbc {
    // The following is the function to create KBC instance object, 
    // which needs to receive KBS URI as a parameter.
    // This function needs to be integrated into KBC_MODULE_LIST of AA,
    // So its parameters and return value format must be implemented according to the example given here.
    fn new(kbs_uri: String) -> MyKbc {...}
    ...
}
```

The detailed KBC module implemention requires to use new KBS protocol to communicate with a new class of KBS through  attestation in order to decrypt the encrypted payload.

## Integration

You need to integrate my_kbc module into AA as following:

1. Import my_kbc module: 

```rust
// kbc/mod.rs

// Add my specific kbc declaration here.
// For example: "pub mod sample_kbc;"
#[cfg(feature = "my_kbc")]
pub mod my_kbc;
```

2. Register the function to create KBC instance in KbcModuleList: 

```rust
// kbc/mod.rs

impl KbcModuleList {
    fn new() -> KbcModuleList {
        let mut mod_list = HashMap::new();

        #[cfg(feature = "my_kbc")]
        {
            let instantiate_func: KbcInstantiateFunc = Box::new(|kbs_uri: String| -> KbcInstance {
                Box::new(my_kbc::MyKbc::new(kbs_uri))
            });
            mod_list.insert("my_kbc".to_string(), instantiate_func);
        }

        KbcModuleList { mod_list: mod_list }
    }
```

3. Add the compilation options for my_kbc in Cargo.toml:

```
# Cargo.toml

[features]
default = ["my_kbc"]
my_kbc = []
```

## Compilation

After development and integration, you can compile the attestation-agent that supports your KBC module. You only need to specify feature parameter during compilation:

```
cargo build --release --no-default-features --features my_kbc
```

