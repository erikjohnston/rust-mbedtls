use std::error;
use std::fmt;

use super::constants::*;
use mbed::error::CError;

create_error!{
    SSLAllocError:
        AllocFailed => MBEDTLS_ERR_SSL_ALLOC_FAILED
}
