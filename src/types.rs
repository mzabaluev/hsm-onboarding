#[derive(Clone, Debug)]
/// A collection of bytes.
pub struct Bytes(pub Vec<u8>);

impl AsRef<[u8]> for Bytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// A signature made with a possibly versioned key.
#[derive(Clone, Debug)]
pub struct Signature {
    /// Key derivation information assigned by the signing module.
    pub derivation: String,
    /// Signature data.
    pub data: Vec<u8>,
}
