extern crate mbedtls;

use mbedtls::mbed;


fn main() {
    let cipher_suite_ids = mbed::ssl::list_ciphersuites();

    for suite_id in cipher_suite_ids {
        println!(
            "0x{:0>5X} {}",
            *suite_id, mbed::ssl::get_ciphersuite_name(*suite_id).to_str().unwrap()
        );
    }
}
