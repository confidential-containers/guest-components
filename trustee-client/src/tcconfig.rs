// Copyright (c) 2024 Alibaba Cloud
// Copyright (c) 2024 Red Hat, Inc
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::{bail, Context, Result};
use config::{Config, File, FileFormat};
use log::{debug, info};
use serde::Deserialize;
use std::fs;
use std::path::Path;

const DEFAULT_TCCONFIG_FILE_PATH: &str = "/etc/trustee-client.conf";
#[derive(Deserialize, Debug, PartialEq)]
pub struct TrusteeClientConfig {
    /// URL Address of Trustee.
    pub url: String,

    /// https:// certificate for Trustee as a string
    pub cert: Option<String>,

    /// https:// certificate for Trustee in a cert_file
    pub cert_file: Option<String>,
}

impl TrusteeClientConfig {
    pub fn new(path_arg: Option<String>) -> Result<Self> {
        let path = match path_arg {
            Some(f) => f,
            None => DEFAULT_TCCONFIG_FILE_PATH.to_string(),
        };

        debug!("Using configuration file {path}");
        if !Path::new(&path).exists() {
            bail!("Config file {path} not found.")
        }

        let c = Config::builder()
            .add_source(File::new(&path as &str, FileFormat::Toml))
            .build()?;

        let tcc: TrusteeClientConfig =
            c.try_deserialize().context("failed to parse config_file")?;

        Ok(tcc)
    }

    // get the certificate from the configuration file, if exists
    // If cert does not exists but cert_file does, read cert from cert_file
    pub fn get_cert(&self) -> Option<String> {
        debug!(
            "cert={:?} cert_file={:?}",
            self.cert.clone(),
            self.cert_file.clone()
        );
        if let Some(c) = &self.cert {
            debug!("Some cert {}", c.clone());
            return Some(c.clone());
        }

        if let Some(cf) = &self.cert_file {
            debug!("Some cert_file {}", cf.clone());
            let newcert = fs::read_to_string(cf.clone()).ok()?;
            return Some(newcert);
        }
        None
    }

    pub fn is_valid(&self) -> Result<()> {
        if self.cert.is_some() && self.cert_file.is_some() {
            bail!("Please provide only one of 'cert' and 'cert_file'");
        }
        if self.url.starts_with("https://") && self.cert.is_none() {
            info!("An https:// URL is used but no certificate is provided");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::TrusteeClientConfig;
    use rstest::rstest;
    use std::fs::File as fsfile;
    use std::io::Write;

    #[rstest]
    #[case::good_http(
        1,
        r#"
url = "http://localhost:50000"
"#,
        Some(TrusteeClientConfig {
            url : "http://localhost:50000".to_string(),
            cert     : None,
            cert_file: None,
        }))]
    #[case::good_https_with_cert(
        2,
        r#"
url = "https://localhost:50000"
cert = "Trustee Certificate"
"#,
        Some(TrusteeClientConfig {
            url      : "https://localhost:50000".to_string(),
            cert     : Some("Trustee Certificate".to_string()),
            cert_file: None,
        })
    )]
    #[case::good_https_with_cert_file(
        3,
        r#"
url = "https://localhost:50000"
cert_file = "/tmp/test_cert_file.conf"
"#,
        Some(TrusteeClientConfig {
            url      : "https://localhost:50000".to_string(),
            cert     : None,
            cert_file: Some("/tmp/test_cert_file.conf".to_string()),
        })
    )]
    #[case::bad_empty(4, r#""#, None)]
    #[case::bad_nourl_only_cert_file(
        5,
        r#"
cert_file = "/tmp/test_cert_file"
"#,
        None
    )]
    fn check_trustee_config_file(
        #[case] n: i32,
        #[case] config: &str,
        #[case] expected: Option<TrusteeClientConfig>,
    ) {
        let testfilename = format!("/tmp/tccconfigtest{n}.conf");
        {
            let mut f = fsfile::create(testfilename.clone()).unwrap();
            f.write_all(config.as_bytes()).unwrap();
            f.sync_all().unwrap();
        } // close f
        let tcc = TrusteeClientConfig::new(Some(testfilename));
        match expected {
            Some(cfg) => assert_eq!(cfg, tcc.unwrap()),
            None => assert!(tcc.is_err()),
        }
    }
}
