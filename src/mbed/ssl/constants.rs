// Manually generated by c+p'ing #define lines from source and shoving it
// through some python:
//
// import re
// lines = literal.strip().split("\n")
// reg = re.compile("#define\s+(\w+)\s+(-0x[0-9A-Fa-f]+)\s+ /\*\*<\s+(.*)\s+\*/")
// print "\n".join(["pub const {:<48}: (i32, &'static str) = ({}, \"{}\");".format(*reg.search(l).groups()) for l in lines])

pub const MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE             : (i32, &'static str) = (-0x7080, "The requested feature is not available.");
pub const MBEDTLS_ERR_SSL_BAD_INPUT_DATA                  : (i32, &'static str) = (-0x7100, "Bad input parameters to function.");
pub const MBEDTLS_ERR_SSL_INVALID_MAC                     : (i32, &'static str) = (-0x7180, "Verification of the message MAC failed.");
pub const MBEDTLS_ERR_SSL_INVALID_RECORD                  : (i32, &'static str) = (-0x7200, "An invalid SSL record was received.");
pub const MBEDTLS_ERR_SSL_CONN_EOF                        : (i32, &'static str) = (-0x7280, "The connection indicated an EOF.");
pub const MBEDTLS_ERR_SSL_UNKNOWN_CIPHER                  : (i32, &'static str) = (-0x7300, "An unknown cipher was received.");
pub const MBEDTLS_ERR_SSL_NO_CIPHER_CHOSEN                : (i32, &'static str) = (-0x7380, "The server has no ciphersuites in common with the client.");
pub const MBEDTLS_ERR_SSL_NO_RNG                          : (i32, &'static str) = (-0x7400, "No RNG was provided to the SSL module.");
pub const MBEDTLS_ERR_SSL_NO_CLIENT_CERTIFICATE           : (i32, &'static str) = (-0x7480, "No client certification received from the client, but required by the authentication mode.");
pub const MBEDTLS_ERR_SSL_CERTIFICATE_TOO_LARGE           : (i32, &'static str) = (-0x7500, "Our own certificate(s) is/are too large to send in an SSL message.");
pub const MBEDTLS_ERR_SSL_CERTIFICATE_REQUIRED            : (i32, &'static str) = (-0x7580, "The own certificate is not set, but needed by the server.");
pub const MBEDTLS_ERR_SSL_PRIVATE_KEY_REQUIRED            : (i32, &'static str) = (-0x7600, "The own private key or pre-shared key is not set, but needed.");
pub const MBEDTLS_ERR_SSL_CA_CHAIN_REQUIRED               : (i32, &'static str) = (-0x7680, "No CA Chain is set, but required to operate.");
pub const MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE              : (i32, &'static str) = (-0x7700, "An unexpected message was received from our peer.");
pub const MBEDTLS_ERR_SSL_FATAL_ALERT_MESSAGE             : (i32, &'static str) = (-0x7780, "A fatal alert message was received from our peer.");
pub const MBEDTLS_ERR_SSL_PEER_VERIFY_FAILED              : (i32, &'static str) = (-0x7800, "Verification of our peer failed.");
pub const MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY               : (i32, &'static str) = (-0x7880, "The peer notified us that the connection is going to be closed.");
pub const MBEDTLS_ERR_SSL_BAD_HS_CLIENT_HELLO             : (i32, &'static str) = (-0x7900, "Processing of the ClientHello handshake message failed.");
pub const MBEDTLS_ERR_SSL_BAD_HS_SERVER_HELLO             : (i32, &'static str) = (-0x7980, "Processing of the ServerHello handshake message failed.");
pub const MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE              : (i32, &'static str) = (-0x7A00, "Processing of the Certificate handshake message failed.");
pub const MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE_REQUEST      : (i32, &'static str) = (-0x7A80, "Processing of the CertificateRequest handshake message failed.");
pub const MBEDTLS_ERR_SSL_BAD_HS_SERVER_KEY_EXCHANGE      : (i32, &'static str) = (-0x7B00, "Processing of the ServerKeyExchange handshake message failed.");
pub const MBEDTLS_ERR_SSL_BAD_HS_SERVER_HELLO_DONE        : (i32, &'static str) = (-0x7B80, "Processing of the ServerHelloDone handshake message failed.");
pub const MBEDTLS_ERR_SSL_BAD_HS_CLIENT_KEY_EXCHANGE      : (i32, &'static str) = (-0x7C00, "Processing of the ClientKeyExchange handshake message failed.");
pub const MBEDTLS_ERR_SSL_BAD_HS_CLIENT_KEY_EXCHANGE_RP   : (i32, &'static str) = (-0x7C80, "Processing of the ClientKeyExchange handshake message failed in DHM / ECDH Read Public.");
pub const MBEDTLS_ERR_SSL_BAD_HS_CLIENT_KEY_EXCHANGE_CS   : (i32, &'static str) = (-0x7D00, "Processing of the ClientKeyExchange handshake message failed in DHM / ECDH Calculate Secret.");
pub const MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE_VERIFY       : (i32, &'static str) = (-0x7D80, "Processing of the CertificateVerify handshake message failed.");
pub const MBEDTLS_ERR_SSL_BAD_HS_CHANGE_CIPHER_SPEC       : (i32, &'static str) = (-0x7E00, "Processing of the ChangeCipherSpec handshake message failed.");
pub const MBEDTLS_ERR_SSL_BAD_HS_FINISHED                 : (i32, &'static str) = (-0x7E80, "Processing of the Finished handshake message failed.");
pub const MBEDTLS_ERR_SSL_ALLOC_FAILED                    : (i32, &'static str) = (-0x7F00, "Memory allocation failed");
pub const MBEDTLS_ERR_SSL_HW_ACCEL_FAILED                 : (i32, &'static str) = (-0x7F80, "Hardware acceleration function returned with error");
pub const MBEDTLS_ERR_SSL_HW_ACCEL_FALLTHROUGH            : (i32, &'static str) = (-0x6F80, "Hardware acceleration function skipped / left alone data");
pub const MBEDTLS_ERR_SSL_COMPRESSION_FAILED              : (i32, &'static str) = (-0x6F00, "Processing of the compression / decompression failed");
pub const MBEDTLS_ERR_SSL_BAD_HS_PROTOCOL_VERSION         : (i32, &'static str) = (-0x6E80, "Handshake protocol not within min/max boundaries");
pub const MBEDTLS_ERR_SSL_BAD_HS_NEW_SESSION_TICKET       : (i32, &'static str) = (-0x6E00, "Processing of the NewSessionTicket handshake message failed.");
pub const MBEDTLS_ERR_SSL_SESSION_TICKET_EXPIRED          : (i32, &'static str) = (-0x6D80, "Session ticket has expired.");
pub const MBEDTLS_ERR_SSL_PK_TYPE_MISMATCH                : (i32, &'static str) = (-0x6D00, "Public key type mismatch (eg, asked for RSA key exchange and presented EC key)");
pub const MBEDTLS_ERR_SSL_UNKNOWN_IDENTITY                : (i32, &'static str) = (-0x6C80, "Unknown identity received (eg, PSK identity)");
pub const MBEDTLS_ERR_SSL_INTERNAL_ERROR                  : (i32, &'static str) = (-0x6C00, "Internal error (eg, unexpected failure in lower-level module)");
pub const MBEDTLS_ERR_SSL_COUNTER_WRAPPING                : (i32, &'static str) = (-0x6B80, "A counter would wrap (eg, too many messages exchanged).");
pub const MBEDTLS_ERR_SSL_WAITING_SERVER_HELLO_RENEGO     : (i32, &'static str) = (-0x6B00, "Unexpected message at ServerHello in renegotiation.");
pub const MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED           : (i32, &'static str) = (-0x6A80, "DTLS client must retry for hello verification");
pub const MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL                : (i32, &'static str) = (-0x6A00, "A buffer is too small to receive or write a message");
pub const MBEDTLS_ERR_SSL_NO_USABLE_CIPHERSUITE           : (i32, &'static str) = (-0x6980, "None of the common ciphersuites is usable (eg, no suitable certificate, see debug messages).");
pub const MBEDTLS_ERR_SSL_WANT_READ                       : (i32, &'static str) = (-0x6900, "Connection requires a read call.");
pub const MBEDTLS_ERR_SSL_WANT_WRITE                      : (i32, &'static str) = (-0x6880, "Connection requires a write call.");
pub const MBEDTLS_ERR_SSL_TIMEOUT                         : (i32, &'static str) = (-0x6800, "The operation timed out.");
pub const MBEDTLS_ERR_SSL_CLIENT_RECONNECT                : (i32, &'static str) = (-0x6780, "The client initiated a reconnect from the same port.");


// ** SETTTINGS **

// Endpoint mode
pub const MBEDTLS_SSL_IS_CLIENT : i32 = 0;
pub const MBEDTLS_SSL_IS_SERVER : i32 = 1;

// transport type
pub const  MBEDTLS_SSL_TRANSPORT_STREAM   : i32 = 0;
pub const  MBEDTLS_SSL_TRANSPORT_DATAGRAM : i32 = 1;

// Presets, unused.
pub const MBEDTLS_SSL_PRESET_DEFAULT : i32 = 0;
pub const MBEDTLS_SSL_PRESET_SUITEB  : i32 = 2;

// Auth mode options.
pub const MBEDTLS_SSL_VERIFY_NONE      : i32 = 0;
pub const MBEDTLS_SSL_VERIFY_OPTIONAL  : i32 = 1;
pub const MBEDTLS_SSL_VERIFY_REQUIRED  : i32 = 2;
pub const MBEDTLS_SSL_VERIFY_UNSET     : i32 = 3; /* Used only for sni_authmode */