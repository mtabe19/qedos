//! TLS policy: TLS 1.3 only, X25519MLKEM768 only, AES-256-GCM only.
//!
//! No cryptographic primitive is implemented here; everything is delegated to
//! OpenSSL (>= 3.5, built in-tree as 3.6.1). The only `unsafe` in the proxy is
//! the FFI to read back the negotiated group, which `rust-openssl` does not
//! expose.

use openssl::ssl::{
    select_next_proto, AlpnError, SslContext, SslContextBuilder, SslFiletype, SslMethod, SslMode,
    SslOptions, SslRef, SslSessionCacheMode, SslVersion,
};
use std::ffi::CStr;
use std::os::raw::c_char;

pub const REQUIRED_GROUP: &str = "X25519MLKEM768";
pub const REQUIRED_CIPHER: &str = "TLS_AES_256_GCM_SHA384";

extern "C" {
    /// OpenSSL >= 3.2: name of the group used for the key exchange of the
    /// current (or resumed) handshake, or NULL.
    fn SSL_get0_group_name(s: *mut openssl_sys::SSL) -> *const c_char;
}

/// Name of the key-exchange group actually negotiated on this connection
/// (e.g. `X25519MLKEM768`). `None` if no handshake has completed.
pub fn negotiated_group(ssl: &SslRef) -> Option<String> {
    use foreign_types::ForeignTypeRef;
    // SAFETY: `ssl.as_ptr()` is a valid SSL* for the lifetime of `ssl`;
    // SSL_get0_group_name returns NULL or a pointer to a static
    // NUL-terminated string owned by the library.
    unsafe {
        let p = SSL_get0_group_name(ssl.as_ptr());
        if p.is_null() {
            return None;
        }
        Some(CStr::from_ptr(p).to_string_lossy().into_owned())
    }
}

pub fn build_context(cert_chain: &str, key: &str) -> Result<SslContext, openssl::error::ErrorStack> {
    let mut b: SslContextBuilder = SslContext::builder(SslMethod::tls_server())?;
    b.set_min_proto_version(Some(SslVersion::TLS1_3))?;
    b.set_max_proto_version(Some(SslVersion::TLS1_3))?;
    b.set_ciphersuites(REQUIRED_CIPHER)?;
    // The *only* supported group. A client that cannot do the hybrid gets a
    // handshake_failure alert; there is no classical fallback (LAW_003).
    b.set_groups_list(REQUIRED_GROUP)?;
    b.set_options(
        SslOptions::NO_COMPRESSION
            | SslOptions::NO_RENEGOTIATION
            | SslOptions::CIPHER_SERVER_PREFERENCE,
    );
    // Early data (0-RTT) disabled.
    b.set_max_early_data(0)?;
    b.set_mode(
        SslMode::RELEASE_BUFFERS | SslMode::ENABLE_PARTIAL_WRITE | SslMode::ACCEPT_MOVING_WRITE_BUFFER,
    );
    // Stateless tickets only; no server-side session cache (memory at C10K).
    b.set_session_cache_mode(SslSessionCacheMode::OFF);
    b.set_alpn_select_callback(|_, client| {
        select_next_proto(b"\x08http/1.1", client).ok_or(AlpnError::NOACK)
    });
    b.set_certificate_chain_file(cert_chain)?;
    b.set_private_key_file(key, SslFiletype::PEM)?;
    b.check_private_key()?;
    Ok(b.build())
}
