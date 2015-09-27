#![feature(libc)]
// #![feature(phase)]

// #![feature(plugin)]
// #![plugin(bindgen_plugin)]

// #![feature(phase)]
// #[phase(plugin)] extern crate bindgen;

extern crate libc;

pub mod mbed;

#[test]
fn it_works() {
    mbed::ssl::SSLContext::new();
    mbed::entropy::EntropyContext::new();
    mbed::ctr_drbg::CtrDrbgContext::new();
}
