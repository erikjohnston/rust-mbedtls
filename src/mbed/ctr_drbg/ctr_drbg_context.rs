use super::bindings;

use ::mbed::entropy;

use std::ptr;
use std::marker::PhantomData;
use std::convert::Into;
use std::slice;
use std::mem::transmute;

use super::error;


extern "C" fn wrap_entropy_callback<F: FnMut(&[u8]) -> Result<(),()>>(
        target: *mut ::libc::c_void,
        output: *mut ::libc::c_uchar, len: ::libc::size_t
    ) -> ::libc::c_int {
    unsafe {
        let mut f : *mut F = transmute(target);
        let r = (*f)(slice::from_raw_parts_mut(output, len as usize));
        match r {
            Ok(()) => 0,
            Err(()) => -1,
        }
    }
}


pub struct CtrDrbgContext<'a> {
    inner: bindings::mbedtls_ctr_drbg_context,
    phantom: PhantomData<&'a entropy::EntropyContext>,
}

impl <'a> CtrDrbgContext<'a> {
    pub fn new() -> Self {
        let mut ctx = CtrDrbgContext {
            inner: bindings::mbedtls_ctr_drbg_context::default(),
            phantom: PhantomData,
        };
        unsafe {
            bindings::mbedtls_ctr_drbg_init(&mut ctx.inner);
        }

        ctx
    }

    pub fn seed<F: FnMut(&[u8]) -> Result<(),()>>(
        &mut self,
        mut entropy_func: Option<&'a mut F>,
        customization: Option<&[u8]>
    ) -> Result<(), error::EntropyError> {
        let r = unsafe {
            match entropy_func {
                Some(func) => bindings::mbedtls_ctr_drbg_seed(
                    &mut self.inner,
                    Some(wrap_entropy_callback::<F>),
                    func as *mut _ as *mut ::libc::c_void,
                    customization.map_or(ptr::null(), |data| data.as_ptr()),
                    customization.map_or(0, |data| data.len() as u64),
                ),
                None => bindings::mbedtls_ctr_drbg_seed(
                    &mut self.inner,
                    None,
                    ptr::null_mut(),
                    customization.map_or(ptr::null(), |data| data.as_ptr()),
                    customization.map_or(0, |data| data.len() as u64),
                )
            }
        };

        match r {
            0 => Ok(()),
            d @ _ => Err(error::EntropyError::from_code(d)),
        }
    }
}

impl <'a> Drop for CtrDrbgContext<'a> {
    fn drop(&mut self) {
        unsafe {
            bindings::mbedtls_ctr_drbg_free(&mut self.inner);
        }
    }
}
