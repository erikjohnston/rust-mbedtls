// use std::io::prelude::*;
use std::net::{Shutdown, TcpStream};
use std::ffi::CString;
use std::thread;
use std::str;

extern crate mbedtls;

use mbedtls::mbed;
use mbedtls::mbed::ssl::error::SSLError;


const TO_WRITE : &'static [u8] = b"GET / HTTP/1.1\r\n\r\n";


fn main() {
    let mut stream = TcpStream::connect("216.58.210.78:443").unwrap();

    {
        let mut entropy = mbedtls::mbed::entropy::EntropyContext::new();
        let mut entropy_func = |d : &mut[u8] | entropy.entropy_func(d);

        let mut ctr_drbg = mbed::ctr_drbg::CtrDrbgContext::with_seed(
            &mut entropy_func, None
        ).unwrap();

        let mut random_func = |f:  &mut[u8] | ctr_drbg.random(f);

        let mut ssl_config = mbed::ssl::SSLConfig::new();
        let mut ssl_context = mbed::ssl::SSLContext::new();

        ssl_config.set_rng(&mut random_func);

        ssl_config.set_defaults(
            mbed::ssl::EndpointType::Client,
            mbed::ssl::TransportType::Stream,
            mbed::ssl::SSLPreset::Default,
        ).unwrap();

        ssl_config.set_authmode(mbed::ssl::AuthMode::VerifyNone);

        ssl_context.setup(&ssl_config).unwrap();

        ssl_context.set_hostname(&CString::new("mbed TLS Server 1").unwrap()).unwrap();

        ssl_context.set_bio_async(&mut stream);

        attempt_io(|| ssl_context.handshake());

        let size_written = attempt_io(|| ssl_context.write(TO_WRITE));
        assert!(size_written == TO_WRITE.len());

        let mut buffer = [0; 4096];
        let size_read = attempt_io(|| ssl_context.read(&mut buffer));

        println!(
            "Read: {} bytes:\n---\n{}\n---",
            size_read, str::from_utf8(&buffer[..size_read]).unwrap()
        );

        attempt_io(|| ssl_context.close_notify());
    }

    stream.shutdown(Shutdown::Both).unwrap();
}


fn attempt_io<I, F: FnMut() -> Result<I, SSLError>>(mut f: F) -> I {
    loop {
        match f() {
            Ok(i) => return i,
            Err(SSLError::WantRead) | Err(SSLError::WantWrite) => {
                thread::sleep_ms(100);
                continue
            },
            Err(e) => panic!("Got error: {}", e),
        }
    }
}
