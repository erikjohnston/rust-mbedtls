use super::bindings;
use super::error;
use std::marker::PhantomData;

use std::ffi::CStr;

use mbed::error::CError;


pub struct SSLContext<'a> {
    inner: bindings::mbedtls_ssl_context,
    phantom: PhantomData<&'a ()>,

}

impl <'a> SSLContext<'a> {
    pub fn new() -> Self {
        let mut ctx = SSLContext {
            inner: bindings::mbedtls_ssl_context::default(),
            phantom: PhantomData,
        };
        unsafe {
            bindings::mbedtls_ssl_init(&mut ctx.inner);
        }

        ctx
    }

    /// Set hostname for ServerName TLS extension (client-side only)
    pub fn set_hostname(&mut self, hostname: &CStr) -> Result<(), error::SSLAllocError> {
        let r = unsafe {
            bindings::mbedtls_ssl_set_hostname(
                &mut self.inner,
                hostname.as_ptr(),
            )
        };

        error::SSLAllocError::from_code(r).map(|_| ())
    }

    // pub fn set_bio_async<
    //     ESend: CError, FSend: FnMut(&[u8]) -> Result<i32, ESend>,
    //     ERead: CError, FRead: FnMut(&mut [u8]) -> Result<i32, ERead>
    // >(&mut self, send_fn: &'a mut FSend, read_fn: &'a mut FRead) {
    //     unsafe {
    //         bindings::mbedtls_ssl_set_bio(
    //             &mut self.inner,
    //             hostname.as_ptr(),
    //         )
    //     };
    // }
}

impl <'a> Drop for SSLContext<'a> {
    fn drop(&mut self) {
        unsafe {
            bindings::mbedtls_ssl_free(&mut self.inner);
        }
    }
}

// extern "C" fn wrap_rng_callback<E, F: FnMut(&mut [u8]) -> Result<(),E>>(
//         target: *mut ::libc::c_void,
//         output: *mut ::libc::c_uchar, len: ::libc::size_t
//     ) -> ::libc::c_int {
//     unsafe {
//         let f : *mut F = transmute(target);
//         let r = (*f)(slice::from_raw_parts_mut(output, len as usize));
//         match r {
//             Ok(()) => 0,
//             Err(_) => -1,
//         }
//     }
// }
