// Copyright (c) 2026 Confidential Containers Authors
//
// SPDX-License-Identifier: Apache-2.0
//

//! This is an AWS KMS / Secrets Manager implementation.
//!
//! - Envelope secrets are backed by [AWS KMS](https://aws.amazon.com/kms/): the
//!   data-encryption-key (DEK) is wrapped/unwrapped via KMS `Encrypt`/`Decrypt`.
//! - Vault secrets are backed by
//!   [AWS Secrets Manager](https://aws.amazon.com/secrets-manager/): the pointed-to
//!   value is fetched via `GetSecretValue`.
//!
//! Both services are reached with the same set of static IAM credentials that are
//! provisioned into the guest (see [`client`] for the credential layout). This
//! mirrors the credential-bootstrap model of the Aliyun and eHSM plugins: the
//! credentials themselves are expected to be delivered into the TEE's encrypted
//! filesystem (e.g. as a sealed secret) before this client is used.

mod annotations;
mod client;
mod credential;

pub use client::AwsKmsClient;
