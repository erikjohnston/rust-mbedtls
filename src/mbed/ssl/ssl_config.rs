use super::bindings;

pub struct SSLConfig {
    inner: bindings::mbedtls_ssl_config,
}

impl SSLConfig {
    pub fn new() -> Self {
        let mut ctx = SSLConfig {
            inner: bindings::mbedtls_ssl_config::default()
        };
        unsafe {
            bindings::mbedtls_ssl_config_init(&mut ctx.inner);
        }

        ctx
    }
}

impl Drop for SSLConfig {
    fn drop(&mut self) {
        unsafe {
            bindings::mbedtls_ssl_config_free(&mut self.inner);
        }
    }
}
