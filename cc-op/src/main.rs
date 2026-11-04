// Copyright (c) 2026 IBM Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use std::process;

use clap::Parser;

use cc_op;

#[derive(Parser, Debug)]
struct Config {
    #[arg(long)]
    payload: String,

    /// Private Key
    #[arg(long)]
    privkey: Option<String>,

    #[arg(long)]
    ccop_toml: String,

    #[arg(long)]
    display: bool,
}

fn main() {
    let config = Config::parse();

    if config.display {
        //println!("{:?}", config);
        println!("main: toml file: {}", config.ccop_toml);
        println!("main: Payload: {}", config.payload);
        if let Some(key) = &config.privkey {
            println!("main: PrivateKey (PEM): {}", key);
        }
        println!("main: Display: {}", config.display);
    }

    let mut vargs: Vec<String> = Vec::new();
    vargs.push("--payload".to_string());
    vargs.push(config.payload.clone());
    if let Some(key) = &config.privkey {
        vargs.push("--privkey".to_string());
        vargs.push(key.clone());
    }
    if config.display {
        println!("main: args {:?}", vargs);
    }

    println!("main: is_ccop_set: {}", cc_op::is_ccop_set());
    println!("main: address of key: {:p}", cc_op::get_ccop_address());

    match cc_op::init_ccop(&config.ccop_toml) {
        Ok(_) => println!("main: Read public key"),
        Err(e) => {
            println!("Error {}", e);
            process::exit(1);
        }
    }

    if !(cc_op::is_agent_private_key_set()) {
        if let Some(key) = &config.privkey {
            println!("main: private key file: {}", key);
            match cc_op::set_receiver_private_key_file(key) {
                Ok(_) => println!("main: Read Receiver private key"),
                Err(e) => {
                    println!("Error {}", e);
                    process::exit(1);
                }
            }
        }
    }

    println!("main: is_ccop_set: {}", cc_op::is_ccop_set());

    match cc_op::verify_ccop_args(vargs) {
        Ok(v) => println!("main: verified_args: {:?}", v),
        Err(e) => println!("main: verify_args: {}", e),
    }
    println!("main: address of key: {:p}", cc_op::get_ccop_address());
}
