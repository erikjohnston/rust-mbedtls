use super::{bindings, constants, error, SSLAlertLevel};
use super::ssl_config::SSLConfig;

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


    pub fn setup(&mut self, config: &'a SSLConfig) -> Result<(), error::SSLAllocError> {
        let r = unsafe {
            bindings::mbedtls_ssl_setup(
                &mut self.inner,
                config.inner(),
            )
        };

        error::SSLAllocError::from_code(r).map(|_| ())
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

    /// Perform the SSL handshake.
    ///
    /// Note:
    /// If this function returns non-zero, then the ssl context becomes unusable, and you should
    /// either free it or call mbedtls_ssl_session_reset() on it before re-using it. If DTLS is in
    /// use, then you may choose to handle MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED specially for
    /// logging purposes, but you still need to reset/free the context.
    pub fn handshake(&mut self) -> Result<(), error::SSLError> {
        let r = unsafe {
            bindings::mbedtls_ssl_handshake(
                &mut self.inner,
            )
        };

        error::SSLError::from_code(r).map(|_| ())
    }

    /// Try to write exactly 'len' application data bytes.
    ///
    /// Warning: This function will do partial writes in some cases. If the return value is
    /// non-negative but less than length, the function must be called again with updated
    /// arguments: buf + ret, len - ret (if ret is the return value) until it returns a value
    /// equal to the last 'len' argument.
    ///
    /// Note:
    /// When this function returns MBEDTLS_ERR_SSL_WANT_WRITE/READ, it must be called later with
    /// the same arguments, until it returns a positive value.
    pub fn write(&mut self, buf: &[u8]) -> Result<usize, error::SSLError> {
        let r = unsafe {
            bindings::mbedtls_ssl_write(
                &mut self.inner,
                buf.as_ptr(), buf.len() as u64
            )
        };

        error::SSLError::from_code(r).map(|i| i as usize)
    }

    /// Read at most 'len' application data bytes.
    ///
    /// Returns: the number of bytes read, or 0 for EOF, or a negative error code.
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize, error::SSLError> {
        let r = unsafe {
            bindings::mbedtls_ssl_read(
                &mut self.inner,
                buf.as_mut_ptr(), buf.len() as u64
            )
        };

        error::SSLError::from_code(r).map(|i| i as usize)
    }

    /// Notify the peer that the connection is being closed.
    pub fn close_notify(&mut self) -> Result<(), error::SSLError> {
        let r = unsafe {
            bindings::mbedtls_ssl_close_notify(&mut self.inner)
        };

        error::SSLError::from_code(r).map(|_| ())
    }

    /// Reset an already initialized SSL context for re-use while retaining application-set
    /// variables, function pointers and data.
    pub fn session_reset(&mut self) -> Result<(), error::SSLError> {
        let r = unsafe {
            bindings::mbedtls_ssl_session_reset(&mut self.inner)
        };

        error::SSLError::from_code(r).map(|_| ())
    }

    /// Initiate an SSL renegotiation on the running connection.
    ///
    /// Client: perform the renegotiation right now.
    /// Server: request renegotiation, which will be performed during the next call to
    /// read() if honored by client.
    pub fn renegotiate(&mut self) -> Result<(), error::SSLError> {
        let r = unsafe {
            bindings::mbedtls_ssl_renegotiate(&mut self.inner)
        };

        error::SSLError::from_code(r).map(|_| ())
    }

    /// Send an alert message
    pub fn send_alert_message(&mut self, level: SSLAlertLevel, message: u8)
    -> Result<(), error::SSLError> {
        let level_char = match level {
            SSLAlertLevel::Warning => constants::MBEDTLS_SSL_ALERT_LEVEL_WARNING,
            SSLAlertLevel::Fatal => constants::MBEDTLS_SSL_ALERT_LEVEL_FATAL,
        };
        let r = unsafe {
            bindings::mbedtls_ssl_send_alert_message(
                &mut self.inner, level_char, message
            )
        };

        error::SSLError::from_code(r).map(|_| ())
    }

    /// Set client's transport-level identification info.
    ///
    /// (Server only. DTLS only.)
    ///
    /// This is usually the IP address (and port), but could be anything identify the client
    /// depending on the underlying network stack. Used for HelloVerifyRequest with DTLS. This is
    /// not used to route the actual packets.
    ///
    /// Returns: SSLError::BadInputData if used on client, SSLError::AllocFailed if out of memory.
    pub fn set_client_transport_id(&mut self, info: &[u8]) -> Result<(), error::SSLError> {
        let r = unsafe {
            bindings::mbedtls_ssl_set_client_transport_id(
                &mut self.inner,
                info.as_ptr(), info.len() as u64
            )
        };

        error::SSLError::from_code(r).map(|_| ())
    }

    /// Get the name of the negotiated Application Layer Protocol.
    ///
    /// This function should be called after the handshake is completed.
    pub fn get_alpn_protocol(&self) -> Option<&'a CStr> {
        unsafe {
            let ret = bindings::mbedtls_ssl_get_alpn_protocol(&self.inner);

            if !ret.is_null() {
                Some(CStr::from_ptr(ret))
            } else {
                None
            }
        }
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
