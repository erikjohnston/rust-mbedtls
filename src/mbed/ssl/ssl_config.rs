use super::bindings;
use super::constants::*;

use mbed::error::CError;
use mbed::error::AllocFailedError;

use std::marker::PhantomData;
use std::mem::transmute;
use std::slice;

/// SSL/TLS configuration to be shared between SSLContext structures
///
/// Corresponds to: mbedtls_ssl_context
pub struct SSLConfig<'a> {
    inner: bindings::mbedtls_ssl_config,
    phantom: PhantomData<&'a ()>,
}

impl <'a> SSLConfig<'a> {
    pub fn new() -> Self {
        let mut ctx = SSLConfig {
            inner: bindings::mbedtls_ssl_config::default(),
            phantom: PhantomData,
        };
        unsafe {
            bindings::mbedtls_ssl_config_init(&mut ctx.inner);
        }

        ctx
    }

    /// Load reasonnable default SSL configuration values.
    pub fn set_defaults(&mut self, endpoint: EndpointType, transport: TransportType, preset: SSLPreset)
    -> Result<(), AllocFailedError> {
        unsafe {
            let r = bindings::mbedtls_ssl_config_defaults(
                &mut self.inner,
                endpoint.to_int(),
                transport.to_int(),
                preset.to_int(),
            );

            AllocFailedError::from_code(r).map(|_| ())
        }
    }

    /// Set authmode for the current handshake.
    pub fn set_authmode(&mut self, auth_mode: AuthMode) {
        unsafe {
            bindings::mbedtls_ssl_conf_authmode(
                &mut self.inner,
                auth_mode.to_int(),
            );
        }
    }

    /// Set the random number generator callback
    pub fn set_rng<F: FnMut(&[u8]) -> Result<(),()>>(
        &mut self,
        mut rng_func: &'a mut F,
    ) {
        unsafe {
            bindings::mbedtls_ssl_conf_rng(
                &mut self.inner,
                Some(wrap_rng_callback::<F>),
                rng_func as *mut _ as *mut ::libc::c_void,
            );
        }
    }
}

impl <'a> Drop for SSLConfig<'a> {
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


/// Wraps a callback for use in mbedtls_ssl_conf_rng
extern "C" fn wrap_rng_callback<F: FnMut(&[u8]) -> Result<(),()>>(
        target: *mut ::libc::c_void,
        output: *mut ::libc::c_uchar, len: ::libc::size_t
    ) -> ::libc::c_int {
    unsafe {
        let f : *mut F = transmute(target);
        let r = (*f)(slice::from_raw_parts_mut(output, len as usize));
        match r {
            Ok(()) => 0,
            Err(()) => -1,
        }
    }
}
