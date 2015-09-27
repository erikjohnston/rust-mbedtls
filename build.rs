extern crate bindgen;

use std::fs::{File, create_dir_all, metadata};
use std::path::Path;
use std::io::{ErrorKind, Write};


const HEADERS : &'static [&'static str] = &["ssl", "entropy", "ctr_drbg"];

const HEADER_BASE : &'static str = "/usr/local/include/mbedtls/";

const MOD_FILE : &'static str = r#"
#[allow(dead_code, non_camel_case_types, non_snake_case, non_upper_case_globals)]
mod bindings;
"#;

fn main() {
    for header in HEADERS.iter() {
        gen(header);
    }
}

fn gen(header: &str) {
    let dir = "src/mbed/".to_string() + header + "/";
    let file = dir.clone() + "bindings.rs";

    create_dir_all(&dir).unwrap();

    let bindings_file = File::create(file).unwrap();

    bindgen::Builder::default()
        .header(HEADER_BASE.to_string() + header + ".h")
        .link("mbedtls")
        .link("mbedx509")
        .link("mbedcrypto")
        .emit_builtins()
        .generate().unwrap()
        .write(Box::new(bindings_file))
        .unwrap();
    ;

    let mod_file_str = dir.clone() + "/mod.rs";
    let metadata = metadata(Path::new(&mod_file_str));
    if let Err(e) = metadata {
        if let ErrorKind::NotFound = e.kind() {
            let mut mod_file = File::create(mod_file_str).unwrap();
            mod_file.write(MOD_FILE.as_bytes()).unwrap();
        }
    }

}
