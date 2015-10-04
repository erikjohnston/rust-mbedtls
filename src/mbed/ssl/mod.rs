/// Bindings for ssl.h

#[allow(dead_code, non_camel_case_types, non_snake_case, non_upper_case_globals)]
mod bindings;
pub mod constants;
pub mod error;

mod ssl_context;
mod ssl_config;
mod x509_cert;

pub use self::ssl_context::*;
pub use self::ssl_config::*;
pub use self::x509_cert::*;


pub enum SSLAlertLevel { Fatal, Warning }
