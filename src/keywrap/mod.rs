// Copyright The ocicrypt Authors.
// SPDX-License-Identifier: Apache-2.0

use crate::config::DecryptConfig;
use crate::config::EncryptConfig;
use anyhow::Result;
use std::collections::HashMap;

#[cfg(feature = "keywrap-jwe")]
pub mod jwe;

/// KeyWrapper is the interface used for wrapping keys using
/// a specific encryption technology (pgp, jwe, pkcs7, pkcs11, keyprovider)
#[allow(unused_variables)]
pub trait KeyWrapper {
    /// wrap keys data with encrypt config.
    fn wrap_keys(&self, ec: &EncryptConfig, opts_data: &[u8]) -> Result<Vec<u8>>;

    /// unwrap keys data with decrypt config.
    fn unwrap_keys(&self, dc: &DecryptConfig, annotation: &[u8]) -> Result<Vec<u8>>;

    /// return the keywraper annotation id.
    fn annotation_id(&self) -> &str;

    /// no_possible_keys returns true if there is no possibility of performing
    /// decryption for parameters provided.
    fn no_possible_keys(&self, dc_param: &HashMap<String, Vec<Vec<u8>>>) -> bool;

    /// private_keys (optional) gets the array of private keys. It is an optional implementation
    /// as in some key services, a private key may not be exportable (i.e. HSM)
    /// If not implemented, return `None`.
    fn private_keys(&self, dc_param: &HashMap<String, Vec<Vec<u8>>>) -> Option<Vec<Vec<u8>>> {
        None
    }

    /// keyids_from_packet (optional) gets a list of key IDs. This is optional as some encryption
    /// schemes may not have a notion of key IDs
    /// If not implemented, return `None`.
    fn keyids_from_packet(&self, packet: String) -> Option<Vec<u64>> {
        None
    }

    /// recipients (optional) gets a list of recipients. It is optional due to the validity of
    /// recipients in a particular encryptiong scheme
    /// If not implemented, return `None`.
    fn recipients(&self, recipients: String) -> Option<Vec<String>> {
        None
    }
}
