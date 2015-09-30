use std::io::prelude::*;
use std::net::TcpStream;

extern crate mbedtls;

use mbedtls::mbed;

fn main() {
    let ssl_context = mbed::ssl::SSLContext::new();
    let mut ssl_config = mbed::ssl::SSLConfig::new();

    let mut entropy = mbedtls::mbed::entropy::EntropyContext::new();
    let mut ctr_drbg = mbed::ctr_drbg::CtrDrbgContext::new();

    ctr_drbg.seed(&mut entropy, None).unwrap();

    let mut stream = TcpStream::connect("127.0.0.1:34254").unwrap();

    ssl_config.set_defaults(
        mbed::ssl::EndpointType::Client,
        mbed::ssl::TransportType::Stream,
        mbed::ssl::SSLPreset::Default,
    ).unwrap();

    ssl_config.set_authmode(mbed::ssl::AuthMode::VerifyNone);

    let _ = stream.write("GET / HTTP/1.1\r\n\r\n".as_bytes());
    let _ = stream.read(&mut [0; 128]);
}
