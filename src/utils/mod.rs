// Copyright The ocicrypt Authors.
// SPDX-License-Identifier: Apache-2.0

#[cfg(feature = "utils-runner")]
pub mod runner;
use anyhow::Result;

#[cfg(feature = "utils-keyprovider")]
pub mod keyprovider;

/// CommandExecuter trait which requires implementation for command exec, first argument is the command name, like /usr/bin/<command-name>,
/// the second is the list of args to pass to it
#[allow(unused_variables)]
pub trait CommandExecuter: Send + Sync {
    fn exec(&self, cmd: String, args: &[String], input: Vec<u8>) -> Result<Vec<u8>>;
}

impl<W: CommandExecuter + ?Sized> CommandExecuter for Box<W> {
    #[inline]
    fn exec(&self, cmd: String, args: &[std::string::String], input: Vec<u8>) -> Result<Vec<u8>> {
        (**self).exec(cmd, args, input)
    }
}
