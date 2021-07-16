// Copyright The ocicrypt Authors.
// SPDX-License-Identifier: Apache-2.0

use crate::utils::CommandExecuter;
use std::io::Write;
use std::process::{Command, Stdio};

#[derive(Debug)]
pub struct Runner {}

impl CommandExecuter for Runner {
    /// ExecuteCommand is used to execute a linux command line command and return the output of the command with an error if it exists.
    fn exec(&self, cmd: String, args: &Vec<String>, input: Vec<u8>) -> std::io::Result<Vec<u8>> {
        let mut child = Command::new(cmd)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()?;

        let mut stdin = child.stdin.take().expect("Failed to open stdin");

        let mut input_copy = input.to_vec();

        std::thread::spawn(move || {
            stdin
                .write_all(input_copy.as_mut_slice())
                .expect("Failed to write to stdin");
        });

        let output = match child.wait_with_output() {
            Ok(o) => o,
            Err(e) => return Err(e)
        };

        Ok(output.stdout)
    }
}
