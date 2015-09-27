use super::bindings;

use ::mbed::entropy;

use std::ptr;
use std::marker::PhantomData;

use super::{error, MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED};


pub struct CtrDrbgContext<'a> {
    inner: bindings::mbedtls_ctr_drbg_context,
    phantom: PhantomData<&'a entropy::EntropyContext>
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

    pub fn seed(&mut self, entropy: &'a mut entropy::EntropyContext, customization: Option<&[u8]>)
    -> Result<(), error::EntropyError> {
        let r = unsafe {
            match customization {
                Some(data) => bindings::mbedtls_ctr_drbg_seed(
                    &mut self.inner,
                    Some(entropy::entropy_func),
                    &mut entropy.inner_mut() as *mut _ as *mut ::libc::c_void,
                    data.as_ptr(),
                    data.len() as u64
                ),
                None => bindings::mbedtls_ctr_drbg_seed(
                    &mut self.inner,
                    Some(entropy::entropy_func),
                    &mut entropy.inner_mut() as *mut _ as *mut ::libc::c_void,
                    ptr::null(),
                    0
                )
            }
        };

        match r {
            0 => Ok(()),
            MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED => Err(error::EntropyError::SourceFailed),
            d @ _ => Err(error::EntropyError::Unknown(d)),
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
