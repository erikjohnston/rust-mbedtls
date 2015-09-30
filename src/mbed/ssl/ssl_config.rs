use super::bindings;
use super::constants::*;

use mbed::error::AllocFailedError;


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

    pub fn set_defaults(&mut self, endpoint: EndpointType, transport: TransportType, preset: SSLPreset)
    -> Result<(), AllocFailedError> {
        unsafe {
            let r = bindings::mbedtls_ssl_config_defaults(
                &mut self.inner,
                endpoint.to_int(),
                transport.to_int(),
                preset.to_int(),
            );

            if r < 0 {
                Err(AllocFailedError::from_code(r))
            } else {
                Ok(())
            }
        }
    }

    pub fn set_authmode(&mut self, auth_mode: AuthMode) {
        unsafe {
            bindings::mbedtls_ssl_conf_authmode(
                &mut self.inner,
                auth_mode.to_int(),
            );
        }
    }
}

impl Drop for SSLConfig {
    fn drop(&mut self) {
        unsafe {
            bindings::mbedtls_ssl_config_free(&mut self.inner);
        }
    }
}


create_enum!{
    EndpointType:
        Server => MBEDTLS_SSL_IS_SERVER,
        Client => MBEDTLS_SSL_IS_CLIENT
}

create_enum!{
    TransportType:
        Stream => MBEDTLS_SSL_TRANSPORT_STREAM,
        Datagram => MBEDTLS_SSL_TRANSPORT_DATAGRAM
}

create_enum!{
    SSLPreset:
        Default => MBEDTLS_SSL_PRESET_DEFAULT,
        SuiteB => MBEDTLS_SSL_PRESET_SUITEB
}

create_enum!{
    AuthMode:
        VerifyNone => MBEDTLS_SSL_VERIFY_NONE,
        VerifyOptional => MBEDTLS_SSL_VERIFY_OPTIONAL,
        VerifyRequired => MBEDTLS_SSL_VERIFY_REQUIRED,
        VerifyUnsey => MBEDTLS_SSL_VERIFY_UNSET
}
