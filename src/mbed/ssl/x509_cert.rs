use super::bindings;

pub struct X509Cert {
    inner: bindings::mbedtls_x509_crt,
}

impl X509Cert {
    pub fn new() -> Self {
        let mut ctx = X509Cert {
            inner: bindings::mbedtls_x509_crt::default()
        };
        unsafe {
            bindings::mbedtls_x509_crt_init(&mut ctx.inner);
        }

        ctx
    }
}

impl Drop for X509Cert {
    fn drop(&mut self) {
        unsafe {
            bindings::mbedtls_x509_crt_free(&mut self.inner);
        }
    }
}
