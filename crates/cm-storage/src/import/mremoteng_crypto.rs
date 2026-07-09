//! mRemoteNG per-field AES-256-GCM decryption (P9.4).
//!
//! mRemoteNG (ConfVersion ≥ 2.6, `BlockCipherMode="GCM"` — the default and the
//! only mode this MVP supports; see `mremoteng.rs`'s module doc for the
//! legacy/`FullFileEncryption` rejection) encrypts each sensitive attribute
//! value (`Password`, the `Protected` canary) independently:
//!
//! 1. `blob = base64_decode(value)`.
//! 2. `salt = blob[0..16]`, `nonce = blob[16..32]` (**16 bytes — not the
//!    usual 12**), `ct_and_tag = blob[32..]` (ciphertext with the 16-byte GCM
//!    tag appended).
//! 3. `key = PBKDF2-HMAC-SHA1(password, salt, iterations, dklen = 32)`
//!    (AES-256 key size). `iterations` comes from the document's
//!    `KdfIterations` attribute (default `1000`) — never hard-coded.
//! 4. `plaintext = AES-256-GCM_decrypt(key, nonce, ct_and_tag, aad = salt)` —
//!    the salt doubles as the AAD.
//!
//! This matches the widely-used `mremoteng_decrypt`-style reference tools
//! (e.g. github.com/haseebT/mRemoteNG-Decrypt, github.com/gquere/mRemoteNG_password_decrypt).
//!
//! **RustCrypto gotcha:** the crate's default [`aes_gcm::Aes256Gcm`] alias is
//! a 12-byte-nonce instantiation and will reject mRemoteNG's 16-byte nonce
//! (wrong-length nonce is a hard `aead` error, not silent truncation) — this
//! module uses the nonce-size-generic form, [`Cipher`], instantiated with
//! [`aes_gcm::aead::consts::U16`] instead.
//!
//! Never logs a password (encryption or decrypted), key, salt, or nonce byte
//! — see the P9.8 §3 secret-safety checklist; only lengths/booleans/error
//! variants are fit to log, and this module doesn't log at all (the caller,
//! `mremoteng.rs`, logs skip/warning *reasons*, never values).

use aes_gcm::AesGcm;
use aes_gcm::aead::{Aead, KeyInit, Payload, consts::U16};
use aes_gcm::aes::Aes256;
use base64::Engine as _;

/// mRemoteNG's built-in default encryption password, used when the user has
/// not set a custom one.
pub(crate) const DEFAULT_PASSWORD: &str = "mR3m";

/// Default `KdfIterations` when the document's root attribute is absent.
pub(crate) const DEFAULT_KDF_ITERATIONS: u32 = 1000;

/// AES-256-GCM with mRemoteNG's non-standard 16-byte nonce (default tag size,
/// `U16`, already matches the scheme).
type Cipher = AesGcm<Aes256, U16>;

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 16;
const TAG_LEN: usize = 16;
/// Minimum valid blob: salt + nonce + tag (a zero-length plaintext still
/// carries a full tag).
const MIN_BLOB_LEN: usize = SALT_LEN + NONCE_LEN + TAG_LEN;

/// Errors from decrypting one mRemoteNG-encrypted attribute value. Never
/// carries the attempted password, key, or any decrypted/plaintext bytes —
/// only lengths and a fixed "auth failed" variant (which covers both a wrong
/// password and corrupt/tampered ciphertext; the GCM tag makes the two
/// indistinguishable, which is the point of an AEAD).
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum MremotengCryptoError {
    #[error("invalid base64 encoding")]
    Base64,
    #[error("encrypted value too short ({0} bytes; need at least {MIN_BLOB_LEN})")]
    TooShort(usize),
    #[error("decryption failed (wrong password, corrupt data, or unsupported scheme)")]
    AuthFailed,
}

/// Decrypts one mRemoteNG-encrypted attribute value (already base64-decoded
/// internally). Never panics on malformed/untrusted input — a too-short blob,
/// bad base64, or a failed GCM auth tag (wrong password) all map to a typed
/// [`MremotengCryptoError`], never garbage plaintext.
pub(crate) fn decrypt_field(
    value_b64: &str,
    password: &str,
    kdf_iterations: u32,
) -> Result<Vec<u8>, MremotengCryptoError> {
    let blob = base64::engine::general_purpose::STANDARD
        .decode(value_b64.trim())
        .map_err(|_| MremotengCryptoError::Base64)?;
    if blob.len() < MIN_BLOB_LEN {
        return Err(MremotengCryptoError::TooShort(blob.len()));
    }

    let salt = &blob[0..SALT_LEN];
    let nonce_bytes = &blob[SALT_LEN..SALT_LEN + NONCE_LEN];
    let ct_and_tag = &blob[SALT_LEN + NONCE_LEN..];

    let mut key = [0u8; 32]; // AES-256 key size
    pbkdf2::pbkdf2_hmac::<sha1::Sha1>(password.as_bytes(), salt, kdf_iterations, &mut key);

    let cipher = Cipher::new_from_slice(&key).map_err(|_| MremotengCryptoError::AuthFailed)?;
    let nonce = aes_gcm::Nonce::<U16>::try_from(nonce_bytes)
        .map_err(|_| MremotengCryptoError::TooShort(blob.len()))?;

    cipher
        .decrypt(
            &nonce,
            Payload {
                msg: ct_and_tag,
                aad: salt,
            },
        )
        .map_err(|_| MremotengCryptoError::AuthFailed)
}

/// Test-only encryption helper — used to (a) prove the round-trip inverse of
/// [`decrypt_field`] and (b) generate the checked-in fixture's ciphertext
/// values (the fixture must contain *valid* encrypted data, which can't be
/// hand-authored). Never called from production code.
#[cfg(test)]
pub(crate) fn encrypt_field_for_test(
    plaintext: &[u8],
    password: &str,
    kdf_iterations: u32,
    salt: [u8; SALT_LEN],
    nonce: [u8; NONCE_LEN],
) -> String {
    let mut key = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<sha1::Sha1>(password.as_bytes(), &salt, kdf_iterations, &mut key);
    let cipher = Cipher::new_from_slice(&key).expect("32-byte key is always valid");
    let nonce_arr = aes_gcm::Nonce::<U16>::try_from(&nonce[..]).expect("16-byte nonce");
    let ct_and_tag = cipher
        .encrypt(
            &nonce_arr,
            Payload {
                msg: plaintext,
                aad: &salt,
            },
        )
        .expect("encryption of a small test payload cannot fail");

    let mut blob = Vec::with_capacity(SALT_LEN + NONCE_LEN + ct_and_tag.len());
    blob.extend_from_slice(&salt);
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ct_and_tag);
    base64::engine::general_purpose::STANDARD.encode(blob)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **Published external vector** (not self-generated): from 0xdf's public
    /// HTB "Bastion" writeup, which quotes a real mRemoteNG `confCons.xml`
    /// `Password` attribute value and its decrypted plaintext —
    /// <https://0xdf.gitlab.io/2019/09/07/htb-bastion.html> ("V22Xa..." →
    /// "thXLHM96BeKL0ER2", decrypted with the default `mR3m` password). This
    /// is what proves the implementation matches files real mRemoteNG
    /// installs actually produce, not just our own encrypt-then-decrypt.
    /// Independently re-verified against a second encrypted value from the
    /// same box (a different HTB Bastion writeup's quoted ciphertext) that
    /// decrypts to the identical plaintext — two independent salts/nonces,
    /// same password, same result.
    #[test]
    fn published_htb_bastion_vector_decrypts_to_known_plaintext() {
        let ciphertext_b64 = "V22XaC5eW4epRxRgXEM5RjuQe2UNrHaZSGMUenOvA1Cit/z3v1fUfZmGMglsiaICSus+bOwJQ/4AnYAt2AeE8g==";
        let plaintext = decrypt_field(ciphertext_b64, DEFAULT_PASSWORD, DEFAULT_KDF_ITERATIONS)
            .expect("the published vector must decrypt cleanly with the default password");
        assert_eq!(plaintext, b"thXLHM96BeKL0ER2");
    }

    /// A second, independently-quoted ciphertext from the very same HTB
    /// Bastion `confCons.xml` (a different writeup/source quoting the
    /// Administrator credential) decrypts to the same plaintext — corroborates
    /// the first vector rather than resting on a single source.
    #[test]
    fn second_independent_htb_bastion_vector_agrees() {
        let ciphertext_b64 = "aEWNFV5uGcjUHF0uS17QTdT9kVqtKCPeoC0Nw5dmaPFjNQ2kt/zO5xDqE4HdVmHAowVRdC7emf7lWWA10dQKiw==";
        let plaintext = decrypt_field(ciphertext_b64, DEFAULT_PASSWORD, DEFAULT_KDF_ITERATIONS)
            .expect("the second published vector must decrypt cleanly too");
        assert_eq!(plaintext, b"thXLHM96BeKL0ER2");
    }

    #[test]
    fn self_round_trip_encrypt_then_decrypt() {
        let salt = [7u8; SALT_LEN];
        let nonce = [9u8; NONCE_LEN];
        let ciphertext = encrypt_field_for_test(
            b"hunter2-plaintext",
            "test-password",
            DEFAULT_KDF_ITERATIONS,
            salt,
            nonce,
        );
        let plaintext = decrypt_field(&ciphertext, "test-password", DEFAULT_KDF_ITERATIONS)
            .expect("round-trip decrypt must succeed");
        assert_eq!(plaintext, b"hunter2-plaintext");
    }

    #[test]
    fn wrong_password_is_a_clean_error_not_a_panic() {
        let ciphertext_b64 = "V22XaC5eW4epRxRgXEM5RjuQe2UNrHaZSGMUenOvA1Cit/z3v1fUfZmGMglsiaICSus+bOwJQ/4AnYAt2AeE8g==";
        let err = decrypt_field(
            ciphertext_b64,
            "definitely-not-the-password",
            DEFAULT_KDF_ITERATIONS,
        )
        .expect_err("a wrong password must fail the GCM auth tag, not decrypt to garbage");
        assert_eq!(err, MremotengCryptoError::AuthFailed);
    }

    #[test]
    fn kdf_iterations_read_from_the_document_not_hardcoded() {
        // A non-default iteration count (2000, vs the 1000 default) must
        // round-trip correctly, proving the caller-supplied `KdfIterations`
        // is what's actually used, not a hardcoded 1000.
        let salt = [3u8; SALT_LEN];
        let nonce = [5u8; NONCE_LEN];
        let ciphertext =
            encrypt_field_for_test(b"custom-iters-secret", "another-pw", 2000, salt, nonce);

        // The default-1000 attempt must fail (proves the value is genuinely
        // iteration-count-sensitive, not just ignored).
        let wrong_iters = decrypt_field(&ciphertext, "another-pw", DEFAULT_KDF_ITERATIONS);
        assert!(wrong_iters.is_err());

        let plaintext = decrypt_field(&ciphertext, "another-pw", 2000)
            .expect("the matching iteration count must decrypt");
        assert_eq!(plaintext, b"custom-iters-secret");
    }

    #[test]
    fn too_short_blob_is_a_clean_error_not_a_panic() {
        let short = base64::engine::general_purpose::STANDARD.encode([0u8; 10]);
        let err = decrypt_field(&short, DEFAULT_PASSWORD, DEFAULT_KDF_ITERATIONS)
            .expect_err("a too-short blob must be rejected cleanly");
        assert_eq!(err, MremotengCryptoError::TooShort(10));
    }

    #[test]
    fn invalid_base64_is_a_clean_error_not_a_panic() {
        let err = decrypt_field(
            "not valid base64 !!!",
            DEFAULT_PASSWORD,
            DEFAULT_KDF_ITERATIONS,
        )
        .expect_err("invalid base64 must be rejected cleanly");
        assert_eq!(err, MremotengCryptoError::Base64);
    }
}
