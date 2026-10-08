use crate::aead::{self, MessageKey};
use crate::identity::{Identity, PublicIdentity, VerifyError};
use crate::kem::{self, HybridPublic, HybridSecret};

pub struct SealedMessage {
    pub sender: Vec<u8>,
    pub x25519_ephemeral: [u8; 32],
    pub mlkem_ciphertext: Vec<u8>,
    pub body: Vec<u8>,
    pub signature: Vec<u8>,
}

pub fn seal_message(sender: &Identity, recipient: &HybridPublic, plaintext: &[u8]) -> SealedMessage {
    let encapsulated = kem::encapsulate(recipient);
    let transcript = transcript(&sender.public().as_bytes(), &encapsulated.x25519_ephemeral, &encapsulated.mlkem_ciphertext);
    let body = aead::seal(&MessageKey(encapsulated.secrets.message_key), &transcript, plaintext);
    let signature = sender.sign(&transcript_with_body(&transcript, &body));
    SealedMessage {
        sender: sender.public().as_bytes().to_vec(),
        x25519_ephemeral: encapsulated.x25519_ephemeral,
        mlkem_ciphertext: encapsulated.mlkem_ciphertext,
        body,
        signature,
    }
}

pub fn open_message(recipient: &HybridSecret, sender: &PublicIdentity, sealed: &SealedMessage) -> Result<Vec<u8>, VerifyError> {
    let transcript = transcript(sender.as_bytes(), &sealed.x25519_ephemeral, &sealed.mlkem_ciphertext);
    sender.verify(&transcript_with_body(&transcript, &sealed.body), &sealed.signature)?;
    let secrets = kem::decapsulate(recipient, &sealed.x25519_ephemeral, &sealed.mlkem_ciphertext);
    aead::open(&MessageKey(secrets.message_key), &transcript, &sealed.body).map_err(|_| VerifyError)
}

fn transcript(sender: &[u8], x25519: &[u8], mlkem: &[u8]) -> Vec<u8> {
    let mut out = b"kestrel transcript v1".to_vec();
    out.extend_from_slice(sender);
    out.extend_from_slice(x25519);
    out.extend_from_slice(mlkem);
    out
}

fn transcript_with_body(transcript: &[u8], body: &[u8]) -> Vec<u8> {
    let mut out = transcript.to_vec();
    out.extend_from_slice(body);
    out
}
