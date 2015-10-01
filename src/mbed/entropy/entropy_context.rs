use super::bindings;

pub struct EntropyContext {
    inner: bindings::mbedtls_entropy_context,
}

impl EntropyContext {
    pub fn new() -> Self {
        let mut ctx = EntropyContext {
            inner: bindings::mbedtls_entropy_context::default()
        };
        unsafe {
            bindings::mbedtls_entropy_init(&mut ctx.inner);
        }

        ctx
    }

    pub fn inner(&self) -> &bindings::mbedtls_entropy_context {
        &self.inner
    }

    pub fn inner_mut(&mut self) -> &mut bindings::mbedtls_entropy_context {
        &mut self.inner
    }

    /// Retrieve entropy from the accumulator
    pub fn entropy_func(&mut self, output: &mut [u8]) -> Result<(),()> {
        let r = unsafe {
            bindings::mbedtls_entropy_func(
                &mut self.inner as * mut _ as *mut ::libc::c_void,
                output.as_mut_ptr(),
                output.len() as u64,
            )
        };

        match r {
           0 => Ok(()),
           _ => Err(()),
        }
    }
}

impl Drop for EntropyContext {
    fn drop(&mut self) {
        unsafe {
            bindings::mbedtls_entropy_free(&mut self.inner);
        }
    }
}
