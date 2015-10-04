use super::bindings;
use super::error;
use std::marker::PhantomData;

use std::ffi::CStr;
use std::io;
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
    pub fn set_bio_async<E : CError, IO : Read<E> + Write<E>>(&mut self, io: &'a mut IO) {
        unsafe {
            bindings::mbedtls_ssl_set_bio(
                &mut self.inner,
                io as *mut _ as *mut ::libc::c_void,
                Some(wrap_bio_send_callback::<E, IO>),
                Some(wrap_bio_read_callback::<E, IO>),
                None,
            );
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


pub trait Write<E: CError> {
    fn write(&mut self, buf: &[u8]) -> Result<usize, E>;
}

pub trait Read<E: CError> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, E>;
}


impl <T: io::Write> Write<io::Error> for T {
    fn write(&mut self, buf: &[u8]) -> Result<usize, io::Error> {
        self.write(buf)
    }
}

impl <T: io::Read> Read<io::Error> for T {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
        self.read(buf)
    }
}

impl CError for io::Error {
    fn to_int(&self) -> i32 {
        match self.kind() {
            io::ErrorKind::WouldBlock => -1,
            _ => -1,
        }
    }
}


extern "C" fn wrap_bio_send_callback<E: CError, IO : Read<E> + Write<E>>(
    target: *mut ::libc::c_void,
    output: *const ::libc::c_uchar, len: ::libc::size_t
) -> ::libc::c_int {
    unsafe {
        let f : *mut IO = transmute(target);
        let r = (*f).write(slice::from_raw_parts(output, len as usize));
        match r {
            Ok(i) => i as i32,
            Err(e) => e.to_int(),
        }
    }
}

extern "C" fn wrap_bio_read_callback<E : CError, IO : Read<E> + Write<E>>(
    target: *mut ::libc::c_void,
    output: *mut ::libc::c_uchar, len: ::libc::size_t
) -> ::libc::c_int {
    unsafe {
        let f : *mut IO = transmute(target);
        let r = (*f).read(slice::from_raw_parts_mut(output, len as usize));
        match r {
            Ok(i) => i as i32,
            Err(e) => e.to_int(),
        }
    }
}
