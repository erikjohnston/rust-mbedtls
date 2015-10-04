use std::error;
use std::fmt;

use super::ssl::constants::*;


// MBEDTLS_ERR_XXX_ALLOC_FAILED
create_error!{
    AllocFailedError:
        SSL => MBEDTLS_ERR_SSL_ALLOC_FAILED
}


pub trait CError : Sized {
    fn to_int(&self) -> i32;
}


impl CError for i32 {
    fn to_int(&self) -> i32 {
        return *self;
    }
}
