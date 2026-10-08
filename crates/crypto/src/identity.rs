use pqcrypto_mldsa::mldsa65;
use pqcrypto_traits::sign::{DetachedSignature, PublicKey as _, SecretKey as _};
use thiserror::Error;

#[derive(Debug, Error)]
#[error("signature rejected")]
pub struct VerifyError;

pub struct Identity {
    public: mldsa65::PublicKey,
        secret: mldsa65::SecretKey,
}

#[derive(Clone)]
pub struct PublicIdentity(mldsa65::PublicKey);

impl Identity {
    pub fn generate() -> Self {
        let (public, secret) = mldsa65::keypair();
        Self { public, secret }
    }

    pub fn public(&self) -> PublicIdentity {
        PublicIdentity(self.public)
    }

    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        mldsa65::detached_sign(message, &self.secret)
        .as_bytes()
        .to_vec()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let public = self.public.as_bytes();
        let secret = self.secret.as_bytes();
        let mut out = (public.len() as u32).to_be_bytes().to_vec();
        out.extend_from_slice(public);
        out.extend_from_slice(secret);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, VerifyError> {
        if bytes.len() < 4 {
            return Err(VerifyError);
        }
        let public_len = u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize;
        if bytes.len() < 4 + public_len {
            return Err(VerifyError);
        }
        let public = mldsa65::PublicKey::from_bytes(&bytes[4..4 + public_len]).map_err(|_| VerifyError)?;
        let secret = mldsa65::SecretKey::from_bytes(&bytes[4 + public_len..]).map_err(|_| VerifyError)?;
        Ok(Self { public, secret })
    }
}

impl PublicIdentity {
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, VerifyError> {
        Ok(Self(
            mldsa65::PublicKey::from_bytes(bytes).map_err(|_| VerifyError)?,
        ))
    }

    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), VerifyError> {
        let signature = mldsa65::DetachedSignature::from_bytes(signature).map_err(|_| VerifyError)?;
        mldsa65::verify_detached_signature(&signature, message, &self.0).map_err(|_| VerifyError)
    }
}
