use std::error;
use std::fmt;

use super::constants::*;
use mbed::error::CError;

create_error!{EntropyError: SourceFailed => MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED}

create_error!{
    RandomError:
        SourceFailed => MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED,
        RequestTooBig => MBEDTLS_ERR_CTR_DRBG_REQUEST_TOO_BIG
}
