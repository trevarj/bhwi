//! BHWI errors while answering Ledger delegated commands.

/// Errors while answering Ledger delegated commands.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// A request without a command byte.
    #[error("empty input")]
    EmptyInput,

    /// An unrecognized delegated command byte.
    #[error("unknown command: {0}")]
    UnknownCommand(
        /// Unrecognized delegated command byte.
        u8,
    ),

    /// A malformed or unsupported delegated request for a recognized command.
    #[error("unsupported request: {0}")]
    UnsupportedRequest(
        /// Recognized delegated command byte, such as `0x40` or `0x41`.
        u8,
    ),

    /// Invalid Merkle index, list size, or request size.
    #[error("invalid index or size")]
    InvalidIndexOrSize,

    /// A hash whose preimage is not registered.
    #[error("unknown hash")]
    UnknownHash,

    /// A Merkle root not registered in the store.
    #[error("unknown merkle root")]
    UnknownMerkleRoot,

    /// A queued fragment state incompatible with the request.
    #[error("unexpected queue state")]
    UnexpectedQueue,
}
