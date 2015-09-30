/* automatically generated by rust-bindgen */

pub type mbedtls_iso_c_forbids_empty_translation_units = ::libc::c_int;
pub type ptrdiff_t = ::libc::c_long;
pub type size_t = ::libc::c_ulong;
pub type wchar_t = ::libc::c_int;
pub type int8_t = ::libc::c_char;
pub type int16_t = ::libc::c_short;
pub type int32_t = ::libc::c_int;
pub type int64_t = ::libc::c_long;
pub type uint8_t = ::libc::c_uchar;
pub type uint16_t = ::libc::c_ushort;
pub type uint32_t = ::libc::c_uint;
pub type uint64_t = ::libc::c_ulong;
pub type int_least8_t = ::libc::c_char;
pub type int_least16_t = ::libc::c_short;
pub type int_least32_t = ::libc::c_int;
pub type int_least64_t = ::libc::c_long;
pub type uint_least8_t = ::libc::c_uchar;
pub type uint_least16_t = ::libc::c_ushort;
pub type uint_least32_t = ::libc::c_uint;
pub type uint_least64_t = ::libc::c_ulong;
pub type int_fast8_t = ::libc::c_char;
pub type int_fast16_t = ::libc::c_long;
pub type int_fast32_t = ::libc::c_long;
pub type int_fast64_t = ::libc::c_long;
pub type uint_fast8_t = ::libc::c_uchar;
pub type uint_fast16_t = ::libc::c_ulong;
pub type uint_fast32_t = ::libc::c_ulong;
pub type uint_fast64_t = ::libc::c_ulong;
pub type intptr_t = ::libc::c_long;
pub type uintptr_t = ::libc::c_ulong;
pub type intmax_t = ::libc::c_long;
pub type uintmax_t = ::libc::c_ulong;
#[repr(C)]
#[derive(Copy)]
pub struct Struct_Unnamed1 {
    pub nr: ::libc::c_int,
    pub rk: *mut uint32_t,
    pub buf: [uint32_t; 68usize],
}
impl ::std::clone::Clone for Struct_Unnamed1 {
    fn clone(&self) -> Self { *self }
}
impl ::std::default::Default for Struct_Unnamed1 {
    fn default() -> Self { unsafe { ::std::mem::zeroed() } }
}
pub type mbedtls_aes_context = Struct_Unnamed1;
#[repr(C)]
#[derive(Copy)]
pub struct Struct_Unnamed2 {
    pub counter: [::libc::c_uchar; 16usize],
    pub reseed_counter: ::libc::c_int,
    pub prediction_resistance: ::libc::c_int,
    pub entropy_len: size_t,
    pub reseed_interval: ::libc::c_int,
    pub aes_ctx: mbedtls_aes_context,
    pub f_entropy: ::std::option::Option<extern "C" fn(arg1:
                                                           *mut ::libc::c_void,
                                                       arg2:
                                                           *mut ::libc::c_uchar,
                                                       arg3: size_t)
                                             -> ::libc::c_int>,
    pub p_entropy: *mut ::libc::c_void,
}
impl ::std::clone::Clone for Struct_Unnamed2 {
    fn clone(&self) -> Self { *self }
}
impl ::std::default::Default for Struct_Unnamed2 {
    fn default() -> Self { unsafe { ::std::mem::zeroed() } }
}
pub type mbedtls_ctr_drbg_context = Struct_Unnamed2;
#[link(name = "mbedtls")]
#[link(name = "mbedx509")]
#[link(name = "mbedcrypto")]
extern "C" {
    pub fn mbedtls_aes_init(ctx: *mut mbedtls_aes_context) -> ();
    pub fn mbedtls_aes_free(ctx: *mut mbedtls_aes_context) -> ();
    pub fn mbedtls_aes_setkey_enc(ctx: *mut mbedtls_aes_context,
                                  key: *const ::libc::c_uchar,
                                  keybits: ::libc::c_uint) -> ::libc::c_int;
    pub fn mbedtls_aes_setkey_dec(ctx: *mut mbedtls_aes_context,
                                  key: *const ::libc::c_uchar,
                                  keybits: ::libc::c_uint) -> ::libc::c_int;
    pub fn mbedtls_aes_crypt_ecb(ctx: *mut mbedtls_aes_context,
                                 mode: ::libc::c_int,
                                 input: *mut ::libc::c_uchar,
                                 output: *mut ::libc::c_uchar)
     -> ::libc::c_int;
    pub fn mbedtls_aes_crypt_cbc(ctx: *mut mbedtls_aes_context,
                                 mode: ::libc::c_int, length: size_t,
                                 iv: *mut ::libc::c_uchar,
                                 input: *const ::libc::c_uchar,
                                 output: *mut ::libc::c_uchar)
     -> ::libc::c_int;
    pub fn mbedtls_aes_crypt_cfb128(ctx: *mut mbedtls_aes_context,
                                    mode: ::libc::c_int, length: size_t,
                                    iv_off: *mut size_t,
                                    iv: *mut ::libc::c_uchar,
                                    input: *const ::libc::c_uchar,
                                    output: *mut ::libc::c_uchar)
     -> ::libc::c_int;
    pub fn mbedtls_aes_crypt_cfb8(ctx: *mut mbedtls_aes_context,
                                  mode: ::libc::c_int, length: size_t,
                                  iv: *mut ::libc::c_uchar,
                                  input: *const ::libc::c_uchar,
                                  output: *mut ::libc::c_uchar)
     -> ::libc::c_int;
    pub fn mbedtls_aes_crypt_ctr(ctx: *mut mbedtls_aes_context,
                                 length: size_t, nc_off: *mut size_t,
                                 nonce_counter: *mut ::libc::c_uchar,
                                 stream_block: *mut ::libc::c_uchar,
                                 input: *const ::libc::c_uchar,
                                 output: *mut ::libc::c_uchar)
     -> ::libc::c_int;
    pub fn mbedtls_aes_encrypt(ctx: *mut mbedtls_aes_context,
                               input: *mut ::libc::c_uchar,
                               output: *mut ::libc::c_uchar) -> ();
    pub fn mbedtls_aes_decrypt(ctx: *mut mbedtls_aes_context,
                               input: *mut ::libc::c_uchar,
                               output: *mut ::libc::c_uchar) -> ();
    pub fn mbedtls_aes_self_test(verbose: ::libc::c_int) -> ::libc::c_int;
    pub fn mbedtls_ctr_drbg_init(ctx: *mut mbedtls_ctr_drbg_context) -> ();
    pub fn mbedtls_ctr_drbg_seed(ctx: *mut mbedtls_ctr_drbg_context,
                                 f_entropy:
                                     ::std::option::Option<extern "C" fn(arg1:
                                                                             *mut ::libc::c_void,
                                                                         arg2:
                                                                             *mut ::libc::c_uchar,
                                                                         arg3:
                                                                             size_t)
                                                               ->
                                                                   ::libc::c_int>,
                                 p_entropy: *mut ::libc::c_void,
                                 custom: *const ::libc::c_uchar, len: size_t)
     -> ::libc::c_int;
    pub fn mbedtls_ctr_drbg_free(ctx: *mut mbedtls_ctr_drbg_context) -> ();
    pub fn mbedtls_ctr_drbg_set_prediction_resistance(ctx:
                                                          *mut mbedtls_ctr_drbg_context,
                                                      resistance:
                                                          ::libc::c_int)
     -> ();
    pub fn mbedtls_ctr_drbg_set_entropy_len(ctx:
                                                *mut mbedtls_ctr_drbg_context,
                                            len: size_t) -> ();
    pub fn mbedtls_ctr_drbg_set_reseed_interval(ctx:
                                                    *mut mbedtls_ctr_drbg_context,
                                                interval: ::libc::c_int)
     -> ();
    pub fn mbedtls_ctr_drbg_reseed(ctx: *mut mbedtls_ctr_drbg_context,
                                   additional: *const ::libc::c_uchar,
                                   len: size_t) -> ::libc::c_int;
    pub fn mbedtls_ctr_drbg_update(ctx: *mut mbedtls_ctr_drbg_context,
                                   additional: *const ::libc::c_uchar,
                                   add_len: size_t) -> ();
    pub fn mbedtls_ctr_drbg_random_with_add(p_rng: *mut ::libc::c_void,
                                            output: *mut ::libc::c_uchar,
                                            output_len: size_t,
                                            additional:
                                                *const ::libc::c_uchar,
                                            add_len: size_t) -> ::libc::c_int;
    pub fn mbedtls_ctr_drbg_random(p_rng: *mut ::libc::c_void,
                                   output: *mut ::libc::c_uchar,
                                   output_len: size_t) -> ::libc::c_int;
    pub fn mbedtls_ctr_drbg_write_seed_file(ctx:
                                                *mut mbedtls_ctr_drbg_context,
                                            path: *const ::libc::c_char)
     -> ::libc::c_int;
    pub fn mbedtls_ctr_drbg_update_seed_file(ctx:
                                                 *mut mbedtls_ctr_drbg_context,
                                             path: *const ::libc::c_char)
     -> ::libc::c_int;
    pub fn mbedtls_ctr_drbg_self_test(verbose: ::libc::c_int)
     -> ::libc::c_int;
    pub fn mbedtls_ctr_drbg_seed_entropy_len(arg1:
                                                 *mut mbedtls_ctr_drbg_context,
                                             arg2:
                                                 ::std::option::Option<extern "C" fn(arg1:
                                                                                         *mut ::libc::c_void,
                                                                                     arg2:
                                                                                         *mut ::libc::c_uchar,
                                                                                     arg3:
                                                                                         size_t)
                                                                           ->
                                                                               ::libc::c_int>,
                                             arg3: *mut ::libc::c_void,
                                             arg4: *const ::libc::c_uchar,
                                             arg5: size_t, arg6: size_t)
     -> ::libc::c_int;
}