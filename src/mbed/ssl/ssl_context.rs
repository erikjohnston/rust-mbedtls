use super::bindings;
use super::error;
use std::marker::PhantomData;

use std::ffi::CStr;
use std::mem::transmute;
use std::slice;

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

    /// Set the underlying BIO callbacks for write and read.
    pub fn set_bio_async<
        ESend: CError, FSend: FnMut(&[u8]) -> Result<i32, ESend>,
        ERead: CError, FRead: FnMut(&mut [u8]) -> Result<i32, ERead>
    >(&mut self, send_fn: &'a mut FSend, read_fn: &'a mut FRead) {
        unsafe {
            let mut cb = BioCallbacks{send: send_fn, read: read_fn};
            bindings::mbedtls_ssl_set_bio(
                &mut self.inner,
                &mut cb as *mut _ as *mut ::libc::c_void,
                Some(wrap_bio_send_callback::<ESend, FSend, ERead, FRead>),
                Some(wrap_bio_read_callback::<ESend, FSend, ERead, FRead>),
                None,
            )
        };
    }
}

impl <'a> Drop for SSLContext<'a> {
    fn drop(&mut self) {
        unsafe {
            bindings::mbedtls_ssl_free(&mut self.inner);
        }
    }
}


struct BioCallbacks<
    ESend: CError, FSend: FnMut(&[u8]) -> Result<i32, ESend>,
    ERead: CError, FRead: FnMut(&mut [u8]) -> Result<i32, ERead>
> {
    pub send: FSend,
    pub read: FRead,
}

extern "C" fn wrap_bio_send_callback<
    ESend: CError, FSend: FnMut(&[u8]) -> Result<i32, ESend>,
    ERead: CError, FRead: FnMut(&mut [u8]) -> Result<i32, ERead>
>(
    target: *mut ::libc::c_void,
    output: *const ::libc::c_uchar, len: ::libc::size_t
) -> ::libc::c_int {
    unsafe {
        let f : *mut BioCallbacks<ESend, FSend, ERead, FRead> = transmute(target);
        let r = ((*f).send)(slice::from_raw_parts(output, len as usize));
        match r {
            Ok(i) => i,
            Err(e) => e.to_int(),
        }
    }
}

extern "C" fn wrap_bio_read_callback<
    ESend: CError, FSend: FnMut(&[u8]) -> Result<i32, ESend>,
    ERead: CError, FRead: FnMut(&mut [u8]) -> Result<i32, ERead>
>(
    target: *mut ::libc::c_void,
    output: *mut ::libc::c_uchar, len: ::libc::size_t
) -> ::libc::c_int {
    unsafe {
        let f : *mut BioCallbacks<ESend, FSend, ERead, FRead> = transmute(target);
        let r = ((*f).read)(slice::from_raw_parts_mut(output, len as usize));
        match r {
            Ok(i) => i,
            Err(e) => e.to_int(),
        }
    }
}
