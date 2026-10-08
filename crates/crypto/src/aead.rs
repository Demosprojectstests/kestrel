use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use thiserror::Error;

#[derive(Clone)]
pub struct MessageKey(pub [u8; 32]);

#[derive(Debug, Error)]
#[error("ciphertext failed authentication")]
pub struct OpenError;

pub fn seal(key: &MessageKey, aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);
    let cipher = XChaCha20Poly1305::new((&key.0).into());
    let body = cipher
    .encrypt(XNonce::from_slice(&nonce), Payload { msg: plaintext, aad })
    .expect("encrypt");
    let mut out = nonce.to_vec();
    out.extend(body);
    out
}

pub fn open(key: &MessageKey, aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>, OpenError> {
    if sealed.len() < 24 {
        return Err(OpenError);
    }
    let (nonce, body) = sealed.split_at(24);
    let cipher = XChaCha20Poly1305::new((&key.0).into());
    cipher
    .decrypt(XNonce::from_slice(nonce), Payload { msg: body, aad })
    .map_err(|_| OpenError)
}

pub fn wrap_prekey(code: &str, prekey: &[u8]) -> Vec<u8> {
    let mut key = [0u8; 32];
    Hkdf::<Sha256>::new(None, code.as_bytes())
    .expand(b"kestrel session wrap v1", &mut key)
    .expect("hkdf");
    seal(&MessageKey(key), b"prekey", prekey)
}

pub fn unwrap_prekey(code: &str, wrapped: &[u8]) -> Result<Vec<u8>, OpenError> {
    let mut key = [0u8; 32];
    Hkdf::<Sha256>::new(None, code.as_bytes())
    .expand(b"kestrel session wrap v1", &mut key)
    .expect("hkdf");
    open(&MessageKey(key), b"prekey", wrapped)
}
