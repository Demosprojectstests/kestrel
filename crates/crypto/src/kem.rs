use hkdf::Hkdf;
use pqcrypto_mlkem::mlkem768;
use pqcrypto_traits::kem::{Ciphertext as _, PublicKey as _, SecretKey as _, SharedSecret as _};
use rand_core::OsRng;
use sha2::Sha256;
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};

pub struct HybridSecret {
    x25519: StaticSecret,
    mlkem: mlkem768::SecretKey,
}

pub struct HybridPublic {
    x25519: PublicKey,
    mlkem: mlkem768::PublicKey,
}

pub struct SharedSecrets {
    pub x25519: [u8; 32],
    pub mlkem: Vec<u8>,
    pub message_key: [u8; 32],
}

pub struct Encapsulated {
    pub x25519_ephemeral: [u8; 32],
    pub mlkem_ciphertext: Vec<u8>,
    pub secrets: SharedSecrets,
}

#[derive(Debug, Error)]
#[error("prekey bytes are the wrong length")]
pub struct PrekeyError;

impl HybridSecret {
    pub fn generate() -> (Self, HybridPublic) {
        let x25519 = StaticSecret::random_from_rng(OsRng);
        let x25519_public = PublicKey::from(&x25519);
        let (mlkem_public, mlkem) = mlkem768::keypair();
        (
            Self { x25519, mlkem },
            HybridPublic {
                x25519: x25519_public,
                mlkem: mlkem_public,
            },
        )
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = self.x25519.to_bytes().to_vec();
        out.extend_from_slice(self.mlkem.as_bytes());
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PrekeyError> {
        if bytes.len() <= 32 {
            return Err(PrekeyError);
        }
        let x25519 = StaticSecret::from(<[u8; 32]>::try_from(&bytes[..32]).unwrap());
        let mlkem = mlkem768::SecretKey::from_bytes(&bytes[32..]).map_err(|_| PrekeyError)?;
        Ok(Self { x25519, mlkem })
    }
}

impl HybridPublic {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = self.x25519.to_bytes().to_vec();
        out.extend_from_slice(self.mlkem.as_bytes());
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PrekeyError> {
        if bytes.len() <= 32 {
            return Err(PrekeyError);
        }
        let x25519 = PublicKey::from(<[u8; 32]>::try_from(&bytes[..32]).unwrap());
        let mlkem = mlkem768::PublicKey::from_bytes(&bytes[32..]).map_err(|_| PrekeyError)?;
        Ok(Self { x25519, mlkem })
    }
}

pub fn encapsulate(their: &HybridPublic) -> Encapsulated {
    let mine = StaticSecret::random_from_rng(OsRng);
    let mine_public = PublicKey::from(&mine);
    let x25519 = mine.diffie_hellman(&their.x25519).to_bytes();
    let (mlkem_secret, mlkem_ciphertext) = mlkem768::encapsulate(&their.mlkem);
    let secrets = derive(&x25519, mlkem_secret.as_bytes());
    Encapsulated {
        x25519_ephemeral: mine_public.to_bytes(),
        mlkem_ciphertext: mlkem_ciphertext.as_bytes().to_vec(),
        secrets,
    }
}

pub fn decapsulate(
    ours: &HybridSecret,
    x25519_ephemeral: &[u8; 32],
    mlkem_ciphertext: &[u8],
) -> SharedSecrets {
    let their = PublicKey::from(*x25519_ephemeral);
    let x25519 = ours.x25519.diffie_hellman(&their).to_bytes();
    let ciphertext =
        mlkem768::Ciphertext::from_bytes(mlkem_ciphertext).expect("ml-kem ciphertext length");
    let mlkem_secret = mlkem768::decapsulate(&ciphertext, &ours.mlkem);
    derive(&x25519, mlkem_secret.as_bytes())
}

fn derive(x25519: &[u8; 32], mlkem: &[u8]) -> SharedSecrets {
    let mut ikm = Vec::with_capacity(32 + mlkem.len());
    ikm.extend_from_slice(x25519);
    ikm.extend_from_slice(mlkem);
    let mut message_key = [0u8; 32];
    Hkdf::<Sha256>::new(None, &ikm)
        .expand(b"kestrel message v1", &mut message_key)
        .expect("hkdf length");
    SharedSecrets {
        x25519: *x25519,
        mlkem: mlkem.to_vec(),
        message_key,
    }
}
