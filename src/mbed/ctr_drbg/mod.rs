/// Bindings for ctr_drbg.h

#[allow(dead_code, non_camel_case_types, non_snake_case, non_upper_case_globals)]
pub mod bindings;
pub mod constants;

mod ctr_drbg_context;

pub mod error;

pub use self::ctr_drbg_context::CtrDrbgContext;


pub extern fn random(
    rng: *mut ::libc::c_void,
    output: *mut ::libc::c_uchar, len: ::libc::size_t
) -> ::libc::c_int {
    unsafe {
        bindings::mbedtls_ctr_drbg_random(rng, output, len)
    }
}
