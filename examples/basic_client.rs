use std::io::prelude::*;
use std::net::TcpStream;
use std::ffi::CString;

extern crate mbedtls;

use mbedtls::mbed;

fn main() {
    let mut entropy = mbedtls::mbed::entropy::EntropyContext::new();
    let mut entropy_func = |d : &mut[u8] | entropy.entropy_func(d);

    let mut ctr_drbg = mbed::ctr_drbg::CtrDrbgContext::new();
    ctr_drbg.seed(&mut entropy_func, None).unwrap();

    let mut random_func = |f:  &mut[u8] | ctr_drbg.random(f);

    let mut ssl_context = mbed::ssl::SSLContext::new();
    let mut ssl_config = mbed::ssl::SSLConfig::new();

    ssl_config.set_rng(&mut random_func);

    let mut stream = TcpStream::connect("127.0.0.1:34254").unwrap();

    ssl_config.set_defaults(
        mbed::ssl::EndpointType::Client,
        mbed::ssl::TransportType::Stream,
        mbed::ssl::SSLPreset::Default,
    ).unwrap();

    ssl_config.set_authmode(mbed::ssl::AuthMode::VerifyNone);

    ssl_context.set_hostname(&CString::new("mbed TLS Server 1").unwrap()).unwrap();

    let _ = stream.write("GET / HTTP/1.1\r\n\r\n".as_bytes());
    let _ = stream.read(&mut [0; 128]);
}
