// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! # Overall
//! For signature verification in Confidential-Containers.
//!
//! # Interfaces
//! #### Image
//! An image struct is a well-encapsulated struct used to do
//! image verification.
//!
//! #### Policy
//! A `Policy` is a policy used to verify the image, usually
//! including signing scheme of the image, or some other rules.
//! 
//! #### SignScheme
//! Sign Scheme for the given signature.

#[macro_use]
extern crate strum;

mod image;
mod mechanism;
mod policy;

pub use image::Image;
pub use policy::Policy;
pub use mechanism::SignScheme;
