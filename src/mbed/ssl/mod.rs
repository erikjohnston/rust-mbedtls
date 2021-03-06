/// Bindings for ssl.h

#[allow(dead_code, non_camel_case_types, non_snake_case, non_upper_case_globals)]
mod bindings;
pub mod constants;
pub mod error;

mod ssl_context;
mod ssl_config;
mod x509_cert;

pub use self::ssl_context::*;
pub use self::ssl_config::*;
pub use self::x509_cert::*;

use std::slice;
use std::ffi::CStr;


pub enum SSLAlertLevel { Fatal, Warning }

#[allow(non_camel_case_types)]
pub enum SSLVersion { SSLv3, TLSv1_0, TLSv1_1, TLSv1_2 }


/// Returns the list of ciphersuites supported by the SSL/TLS module.
pub fn list_ciphersuites() -> &'static [i32] {
    unsafe {
        let suite_ids = bindings::mbedtls_ssl_list_ciphersuites();

        let mut length = 0;
        while *suite_ids.offset(length as isize) != 0 {
            length += 1;
        }

        slice::from_raw_parts(suite_ids, length)
    }
}


/// Return the name of the ciphersuite associated with the given ID.
pub fn get_ciphersuite_name(suite_id: i32) -> &'static CStr {
    unsafe {
        let name = bindings::mbedtls_ssl_get_ciphersuite_name(suite_id);

        CStr::from_ptr(name)
    }
}


/// Return the ID of the ciphersuite associated with the given name.
pub fn get_ciphersuite_id(ciphersuite_name: &CStr) -> i32 {
    unsafe {
        bindings::mbedtls_ssl_get_ciphersuite_id(ciphersuite_name.as_ptr())
    }
}
