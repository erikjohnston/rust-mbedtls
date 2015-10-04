use std::error;
use std::fmt;

use super::constants::*;
use mbed::error::CError;

create_error!{
    SSLAllocError:
        AllocFailed => MBEDTLS_ERR_SSL_ALLOC_FAILED
}

create_error!{
    SSLError:
        FeatureUnavailable        => MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE,
        BadInputData              => MBEDTLS_ERR_SSL_BAD_INPUT_DATA,
        InvalidMac                => MBEDTLS_ERR_SSL_INVALID_MAC,
        InvalidRecord             => MBEDTLS_ERR_SSL_INVALID_RECORD,
        ConnEof                   => MBEDTLS_ERR_SSL_CONN_EOF,
        UnknownCipher             => MBEDTLS_ERR_SSL_UNKNOWN_CIPHER,
        NoCipherChosen            => MBEDTLS_ERR_SSL_NO_CIPHER_CHOSEN,
        NoRng                     => MBEDTLS_ERR_SSL_NO_RNG,
        NoClientCertificate       => MBEDTLS_ERR_SSL_NO_CLIENT_CERTIFICATE,
        CertificateTooLarge       => MBEDTLS_ERR_SSL_CERTIFICATE_TOO_LARGE,
        CertificateRequired       => MBEDTLS_ERR_SSL_CERTIFICATE_REQUIRED,
        PrivateKeyRequired        => MBEDTLS_ERR_SSL_PRIVATE_KEY_REQUIRED,
        CaChainRequired           => MBEDTLS_ERR_SSL_CA_CHAIN_REQUIRED,
        UnexpectedMessage         => MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE,
        FatalAlertMessage         => MBEDTLS_ERR_SSL_FATAL_ALERT_MESSAGE,
        PeerVerifyFailed          => MBEDTLS_ERR_SSL_PEER_VERIFY_FAILED,
        PeerCloseNotify           => MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY,
        BadHsClientHello          => MBEDTLS_ERR_SSL_BAD_HS_CLIENT_HELLO,
        BadHsServerHello          => MBEDTLS_ERR_SSL_BAD_HS_SERVER_HELLO,
        BadHsCertificate          => MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE,
        BadHsCertificateRequest   => MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE_REQUEST,
        BadHsServerKeyExchange    => MBEDTLS_ERR_SSL_BAD_HS_SERVER_KEY_EXCHANGE,
        BadHsServerHelloDone      => MBEDTLS_ERR_SSL_BAD_HS_SERVER_HELLO_DONE,
        BadHsClientKeyExchange    => MBEDTLS_ERR_SSL_BAD_HS_CLIENT_KEY_EXCHANGE,
        BadHsClientKeyExchangeRp  => MBEDTLS_ERR_SSL_BAD_HS_CLIENT_KEY_EXCHANGE_RP,
        BadHsClientKeyExchangeCs  => MBEDTLS_ERR_SSL_BAD_HS_CLIENT_KEY_EXCHANGE_CS,
        BadHsCertificateVerify    => MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE_VERIFY,
        BadHsChangeCipherSpec     => MBEDTLS_ERR_SSL_BAD_HS_CHANGE_CIPHER_SPEC,
        BadHsFinished             => MBEDTLS_ERR_SSL_BAD_HS_FINISHED,
        AllocFailed               => MBEDTLS_ERR_SSL_ALLOC_FAILED,
        HwAccelFailed             => MBEDTLS_ERR_SSL_HW_ACCEL_FAILED,
        HwAccelFallthrough        => MBEDTLS_ERR_SSL_HW_ACCEL_FALLTHROUGH,
        CompressionFailed         => MBEDTLS_ERR_SSL_COMPRESSION_FAILED,
        BadHsProtocolVersion      => MBEDTLS_ERR_SSL_BAD_HS_PROTOCOL_VERSION,
        BadHsNewSessionTicket     => MBEDTLS_ERR_SSL_BAD_HS_NEW_SESSION_TICKET,
        SessionTicketExpired      => MBEDTLS_ERR_SSL_SESSION_TICKET_EXPIRED,
        PkTypeMismatch            => MBEDTLS_ERR_SSL_PK_TYPE_MISMATCH,
        UnknownIdentity           => MBEDTLS_ERR_SSL_UNKNOWN_IDENTITY,
        InternalError             => MBEDTLS_ERR_SSL_INTERNAL_ERROR,
        CounterWrapping           => MBEDTLS_ERR_SSL_COUNTER_WRAPPING,
        WaitingServerHelloRenego  => MBEDTLS_ERR_SSL_WAITING_SERVER_HELLO_RENEGO,
        HelloVerifyRequired       => MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED,
        BufferTooSmall            => MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL,
        NoUsableCiphersuite       => MBEDTLS_ERR_SSL_NO_USABLE_CIPHERSUITE,
        WantRead                  => MBEDTLS_ERR_SSL_WANT_READ,
        WantWrite                 => MBEDTLS_ERR_SSL_WANT_WRITE,
        Timeout                   => MBEDTLS_ERR_SSL_TIMEOUT,
        ClientReconnect           => MBEDTLS_ERR_SSL_CLIENT_RECONNECT
}
