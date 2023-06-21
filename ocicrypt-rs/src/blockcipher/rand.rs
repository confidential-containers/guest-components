// Copyright The ocicrypt Authors.
// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;

/// Fill the given slice with cryptographically generated random numbers
pub(crate) fn rand_bytes(data: &mut [u8]) -> Result<()> {
    cfg_if::cfg_if! {
        if #[cfg(feature = "block-cipher-openssl")] {
            openssl::rand::rand_bytes(&mut data[..])?;
        } else if #[cfg(feature = "block-cipher-ring")] {
            use ring::rand::SecureRandom;
            ring::rand::SystemRandom::new().fill(&mut data[..]).map_err(|e| anyhow::anyhow!(e.to_string()))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod test {
    use crate::blockcipher::rand::rand_bytes;

    #[test]
    fn fill_random_bytes() {
        let mut data = vec![9; 0];
        assert!(rand_bytes(&mut data).is_ok());
    }
}
