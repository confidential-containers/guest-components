// Copyright (c) 2026 XHawk Corp
//
// SPDX-License-Identifier: Apache-2.0
//

use std::sync::{Arc, Mutex, OnceLock};

use base64::Engine;
use serde_json::json;

use super::*;

const DOCUMENT: &[u8] = b"cose-sign1-attestation-document";

/// One attestation request: its `nonce` and `user_data`.
type NsmRequest = (Vec<u8>, Option<Vec<u8>>);

/// A fake NSM that records each request and returns a fixed document.
#[derive(Clone, Default)]
struct FakeNsm {
    requests: Arc<Mutex<Vec<NsmRequest>>>,
    fail: bool,
}

impl Nsm for FakeNsm {
    fn attestation(&self, nonce: Vec<u8>, user_data: Option<Vec<u8>>) -> Result<Vec<u8>> {
        self.requests.lock().unwrap().push((nonce, user_data));
        if self.fail {
            bail!("NSM returned InvalidOperation");
        }
        Ok(DOCUMENT.to_vec())
    }
}

/// A binding of its own per test, so tests don't share the process-wide one.
fn fresh_binding() -> &'static OnceLock<Vec<u8>> {
    Box::leak(Box::new(OnceLock::new()))
}

fn attester() -> (NitroEnclaveAttester, FakeNsm) {
    let nsm = FakeNsm::default();
    (
        NitroEnclaveAttester::with_nsm(Box::new(nsm.clone()), fresh_binding()),
        nsm,
    )
}

#[tokio::test]
async fn a_digest_bound_through_one_instance_is_sent_by_another() {
    // The AA binds InitData on its primary attester, but its KBS token path
    // builds a fresh attester (NativeEvidenceProvider::new). Both must see
    // the binding.
    let binding = fresh_binding();
    let nsm = FakeNsm::default();
    let first = NitroEnclaveAttester::with_nsm(Box::new(nsm.clone()), binding);
    first.bind_init_data(&[0x22; 32]).await.unwrap();

    let second = NitroEnclaveAttester::with_nsm(Box::new(nsm.clone()), binding);
    second.get_evidence(vec![0x11; 48]).await.unwrap();
    assert_eq!(nsm.requests.lock().unwrap()[0].1, Some(vec![0x22; 32]));
}

#[test]
fn default_instances_share_one_process_wide_binding() {
    let a = NitroEnclaveAttester::default();
    let b = NitroEnclaveAttester::default();
    assert!(std::ptr::eq(a.binding, b.binding));
}

#[tokio::test]
async fn evidence_wraps_the_nsm_document() {
    let (attester, _) = attester();
    let evidence = attester.get_evidence(vec![0x11; 48]).await.unwrap();
    assert_eq!(
        evidence,
        json!({
            "version": 1,
            "attestation_document": base64::engine::general_purpose::STANDARD.encode(DOCUMENT),
        })
    );
}

#[tokio::test]
async fn report_data_is_sent_as_the_nonce_unchanged() {
    let (attester, nsm) = attester();
    attester.get_evidence(vec![0x11; 48]).await.unwrap();
    let requests = nsm.requests.lock().unwrap();
    assert_eq!(*requests, vec![(vec![0x11; 48], None)]);
}

#[tokio::test]
async fn a_bound_init_data_digest_is_sent_as_user_data() {
    let (attester, nsm) = attester();
    assert_eq!(
        attester.bind_init_data(&[0x22; 32]).await.unwrap(),
        InitDataResult::Ok
    );
    attester.get_evidence(vec![0x11; 48]).await.unwrap();
    attester.get_evidence(vec![0x33; 48]).await.unwrap();
    let requests = nsm.requests.lock().unwrap();
    assert_eq!(
        *requests,
        vec![
            (vec![0x11; 48], Some(vec![0x22; 32])),
            (vec![0x33; 48], Some(vec![0x22; 32])),
        ]
    );
}

#[tokio::test]
async fn binding_the_same_digest_again_is_accepted() {
    let (attester, _) = attester();
    attester.bind_init_data(&[0x22; 32]).await.unwrap();
    assert_eq!(
        attester.bind_init_data(&[0x22; 32]).await.unwrap(),
        InitDataResult::Ok
    );
}

#[tokio::test]
async fn binding_a_different_digest_is_refused_and_keeps_the_first() {
    let (attester, nsm) = attester();
    attester.bind_init_data(&[0x22; 32]).await.unwrap();
    let err = attester.bind_init_data(&[0x44; 32]).await.unwrap_err();
    assert!(err.to_string().contains("already bound"), "{err:#}");

    attester.get_evidence(vec![0x11; 48]).await.unwrap();
    assert_eq!(nsm.requests.lock().unwrap()[0].1, Some(vec![0x22; 32]));
}

#[tokio::test]
async fn report_data_over_512_bytes_is_refused_before_the_nsm() {
    let (attester, nsm) = attester();
    let err = attester.get_evidence(vec![0x11; 513]).await.unwrap_err();
    assert!(err.to_string().contains("512"), "{err:#}");
    assert!(nsm.requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn an_init_data_digest_over_512_bytes_is_refused() {
    let (attester, _) = attester();
    let err = attester.bind_init_data(&[0x22; 513]).await.unwrap_err();
    assert!(err.to_string().contains("512"), "{err:#}");
}

#[tokio::test]
async fn an_empty_init_data_digest_is_refused() {
    let (attester, _) = attester();
    assert!(attester.bind_init_data(&[]).await.is_err());
}

#[tokio::test]
async fn nsm_errors_are_propagated() {
    let nsm = FakeNsm {
        fail: true,
        ..Default::default()
    };
    let attester = NitroEnclaveAttester::with_nsm(Box::new(nsm), fresh_binding());
    let err = attester.get_evidence(vec![0x11; 48]).await.unwrap_err();
    assert!(format!("{err:#}").contains("InvalidOperation"), "{err:#}");
}

#[test]
fn the_tee_maps_to_this_attester() {
    assert!(crate::BoxedAttester::try_from(kbs_types::Tee::AwsNitroEnclave).is_ok());
}

#[test]
fn a_missing_nsm_device_is_reported_with_its_cause() {
    if std::path::Path::new(NSM_DEVICE).exists() {
        return; // inside an enclave the device opens
    }
    let err = DevNsm.attestation(vec![0; 48], None).unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("failed to open /dev/nsm: "), "{msg}");
    assert!(msg.contains("No such file or directory"), "{msg}");
}
