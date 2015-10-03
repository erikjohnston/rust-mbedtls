use std::error;
use std::fmt;

use super::ssl::constants::*;


// MBEDTLS_ERR_XXX_ALLOC_FAILED
create_error!{
    AllocFailedError:
        SSL => MBEDTLS_ERR_SSL_ALLOC_FAILED
}


pub trait CError : Sized {
    fn from_code(err_code : i32) -> Result<i32, Self>;
    fn to_int(&self) -> i32;
}


impl CError for i32 {
    fn from_code(err_code : i32) -> Result<i32, Self> {
        if err_code >= 0 {
            Ok(err_code)
        } else {
            Err(err_code)
        }
    }

    fn to_int(&self) -> i32 {
        return *self;
    }
}
