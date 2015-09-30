use std::error;
use std::fmt;

use super::constants::*;

create_error!{EntropyError: SourceFailed => MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED}
