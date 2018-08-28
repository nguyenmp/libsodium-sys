// This project's build script

use std::env;
use std::process::Command;
use std::path::PathBuf;

fn main() {
    // Cargo tells us where to put build artifacts
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    println!("OutDir={}", out_dir.to_str().unwrap());

    // libs and includes is the path to the build artifacts
    // these will need to be passed up to cargo for linking
    let mut libs = PathBuf::from(&out_dir);
    libs.push("lib");
    let mut includes = PathBuf::from(&out_dir);
    includes.push("include");

    // The path to the libsodium source
    let lib_sodium_dir = "./libsodium-stable/";

    // configure && make && make install
    Command::new("./configure")
            .current_dir(lib_sodium_dir)
            .arg(format!("--prefix={}", out_dir.to_str().unwrap()))
            .status().unwrap();
    Command::new("make")
            .current_dir(lib_sodium_dir)
            .status().unwrap();
    Command::new("make")
            .arg("install")
            .current_dir(lib_sodium_dir)
            .status().unwrap();

    // Output for the rust compiler how to compile and link to libsodium
    println!("cargo:rustc-link-lib=static=sodium");
    println!("cargo:rustc-link-search={}", libs.to_str().unwrap());
    println!("cargo:rerun-if-changed={}", lib_sodium_dir);
    println!("cargo:rerun-if-changed={}", out_dir.to_str().unwrap());
}
