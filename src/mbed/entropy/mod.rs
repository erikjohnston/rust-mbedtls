
#[allow(dead_code, non_camel_case_types, non_snake_case, non_upper_case_globals)]
pub mod bindings;

mod entropy_context;

pub use self::entropy_context::EntropyContext;


pub extern fn entropy_func(
    data: *mut ::libc::c_void,
    output: *mut ::libc::c_uchar, len: ::libc::size_t
) -> ::libc::c_int {
    unsafe {
        bindings::mbedtls_entropy_func(data, output, len)
    }
}
