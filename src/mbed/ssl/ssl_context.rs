use super::bindings;

pub struct SSLContext {
    inner: bindings::mbedtls_ssl_context,
}

impl SSLContext {
    pub fn new() -> Self {
        let mut ctx = SSLContext {
            inner: bindings::mbedtls_ssl_context::default()
        };
        unsafe {
            bindings::mbedtls_ssl_init(&mut ctx.inner);
        }

        ctx
    }
}

impl Drop for SSLContext {
    fn drop(&mut self) {
        unsafe {
            bindings::mbedtls_ssl_free(&mut self.inner);
        }
    }
}
