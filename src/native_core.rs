use crate::contract::{ExternalSignerBackend, SignerError, SignerRequest, SignerResponse};

pub struct NativeSignerAdapter;

impl ExternalSignerBackend for NativeSignerAdapter {
    fn call(&self, _req: SignerRequest) -> Result<SignerResponse, SignerError> {
        Err(SignerError::Unsupported(
            "Native adapter scaffold: not implemented".to_string(),
        ))
    }
}
