use super::bindings;

use ::mbed::entropy;

use std::ptr;
use std::marker::PhantomData;
use std::slice;
use std::mem::transmute;

use super::error;


/// CTR_DRBG context structure
pub struct CtrDrbgContext<'a> {
    inner: bindings::mbedtls_ctr_drbg_context,
    phantom: PhantomData<&'a entropy::EntropyContext>,
}


impl <'a> CtrDrbgContext<'a> {
    pub fn with_seed<E, F: FnMut(&mut[u8]) -> Result<(),E>>(
        mut entropy_func: &'a mut F,
        customization: Option<&[u8]>
    ) -> Result<Self, error::EntropyError> {
        let mut ctx = CtrDrbgContext {
            inner: bindings::mbedtls_ctr_drbg_context::default(),
            phantom: PhantomData,
        };

        unsafe {
            bindings::mbedtls_ctr_drbg_init(&mut ctx.inner);
        }

        try!(ctx.seed(entropy_func, customization));

        Ok(ctx)
    }

    /// CTR_DRBG initial seeding Seed and setup entropy source for future reseeds
    ///
    /// Corresponds to: mbedtls_ctr_drbg_seed
    pub fn seed<E, F: FnMut(&mut[u8]) -> Result<(), E>>(
        &mut self,
        mut entropy_func: &'a mut F,
        customization: Option<&[u8]>
    ) -> Result<(), error::EntropyError> {

        let (custom_ptr, custom_len) = match customization {
            Some(d) => (d.as_ptr(), d.len() as u64),
            None => (ptr::null(), 0),
        };

        let r = unsafe {
            bindings::mbedtls_ctr_drbg_seed(
                &mut self.inner,
                Some(wrap_entropy_callback::<E, F>),
                entropy_func as *mut _ as *mut ::libc::c_void,
                custom_ptr,
                custom_len,
            )
        };

        error::EntropyError::from_code(r).map(|_| ())
    }

    /// CTR_DRBG generate random.
    ///
    /// Note: Automatically reseeds if reseed_counter is reached.
    pub fn random(&mut self, output: &mut [u8]) -> Result<(), error::RandomError> {
        let r = unsafe {
            bindings::mbedtls_ctr_drbg_random(
                &mut self.inner as *mut _ as *mut ::libc::c_void,
                output.as_mut_ptr(),
                output.len() as u64,
            )
        };

        error::RandomError::from_code(r).map(|_| ())
    }
}

impl <'a> Drop for CtrDrbgContext<'a> {
    fn drop(&mut self) {
        unsafe {
            bindings::mbedtls_ctr_drbg_free(&mut self.inner);
        }
    }
}


/// Wraps a callback for use in mbedtls_ctr_drbg_seed
extern "C" fn wrap_entropy_callback<E, F: FnMut(&mut [u8]) -> Result<(), E>>(
        target: *mut ::libc::c_void,
        output: *mut ::libc::c_uchar, len: ::libc::size_t
    ) -> ::libc::c_int {
    unsafe {
        let f : *mut F = transmute(target);
        let r = (*f)(slice::from_raw_parts_mut(output, len as usize));
        match r {
            Ok(()) => 0,
            Err(_) => -1,
        }
    }
}
