//! Ledger wallet policy encoding and single-key policy construction.

use core::str::FromStr;

use bitcoin::bip32::{ChildNumber, DerivationPath, Fingerprint, Xpub};

use miniscript::descriptor::{KeyInfo, WalletPolicy, WalletPolicyError};

/// Ledger wallet policy wire-format version.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Version {
    /// Version 1, embedding the descriptor template.
    V1 = 1,
    /// Version 2, committing to the descriptor template's SHA-256 hash.
    V2 = 2,
}

/// Bitcoin address families used by Ledger wallet policies.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AddressType {
    /// Legacy address type. P2PKH for single sig, P2SH for scripts.
    Legacy,
    /// Native SegWit v0: P2WPKH for single keys and P2WSH for scripts.
    NativeSegwit,
    /// Wrapped SegWit v0: P2SH-P2WPKH for single keys and P2SH-P2WSH for scripts.
    NestedSegwit,
    /// Segwit v1 Taproot address type. P2TR always.
    Taproot,
}

/// Ledger-specific wallet policy encoding.
///
/// Wraps a miniscript `WalletPolicy` with Ledger-specific metadata (name, version)
/// and provides the wire-format serialization that the Ledger Bitcoin app expects.
#[derive(Clone, Debug)]
pub struct LedgerWalletPolicy {
    /// User-visible wallet name; standard unnamed policies use an empty string.
    pub name: String,
    /// Wallet policy wire-format version.
    pub version: Version,
    /// Descriptor template and resolved keys.
    pub policy: WalletPolicy,
}

impl LedgerWalletPolicy {
    /// Creates a policy wrapper without validating firmware-specific constraints.
    pub fn new(name: String, version: Version, policy: WalletPolicy) -> Self {
        Self {
            name,
            version,
            policy,
        }
    }

    pub(super) fn to_vendor(
        &self,
    ) -> Result<ledger_bitcoin_client::wallet::WalletPolicy, WalletError> {
        use ledger_bitcoin_client::wallet::{Version as VendorVersion, WalletPubKey};
        let (template, keys) = crate::policy::extract_parts(&self.policy)?;
        let keys = keys
            .iter()
            .map(|key| {
                let (fingerprint, path, inner) =
                    crate::policy::xpub_origin(key).ok_or(WalletError::InvalidPolicy)?;
                Ok(WalletPubKey {
                    inner,
                    source: fingerprint.zip(path),
                    // Multipath suffixes belong to the extracted template, not KEY_INFO.
                    multipath: None,
                })
            })
            .collect::<Result<Vec<_>, WalletError>>()?;
        Ok(ledger_bitcoin_client::wallet::WalletPolicy::new(
            self.name.clone(),
            match self.version {
                Version::V1 => VendorVersion::V1,
                Version::V2 => VendorVersion::V2,
            },
            template,
            keys,
        ))
    }

    /// Serializes the policy with its descriptor commitment and key Merkle root.
    ///
    /// The name byte length is cast to `u8` without range validation.
    pub fn serialize(&self) -> Result<Vec<u8>, WalletError> {
        Ok(self.to_vendor()?.serialize())
    }

    /// Returns the SHA-256 digest of the serialized policy.
    pub fn id(&self) -> Result<[u8; 32], WalletError> {
        Ok(self.to_vendor()?.id())
    }
}

/// Construct a `WalletPolicy` from a single-sig derivation path, fingerprint, and xpub.
///
/// This creates a standard BIP-44/49/84/86 wallet policy based on the purpose
/// field of the derivation path. The path must be at least 5 levels deep
/// (purpose/coin_type/account/change/index).
pub fn singlesig_wallet_policy(
    path: &DerivationPath,
    fingerprint: Fingerprint,
    xpub: Xpub,
) -> Result<WalletPolicy, WalletError> {
    let children: &[ChildNumber] = path.as_ref();
    if children.len() < 5 {
        return Err(WalletError::InvalidPolicy);
    }

    let account_path: Vec<ChildNumber> = children[..3].to_vec();
    let account_derivation = DerivationPath::from(account_path);

    let descriptor_template = match children[0] {
        c if c == ChildNumber::from_hardened_idx(86).unwrap() => "tr(@0/**)",
        c if c == ChildNumber::from_hardened_idx(84).unwrap() => "wpkh(@0/**)",
        c if c == ChildNumber::from_hardened_idx(49).unwrap() => "sh(wpkh(@0/**))",
        c if c == ChildNumber::from_hardened_idx(44).unwrap() => "pkh(@0/**)",
        _ => return Err(WalletError::UnsupportedAddressType),
    };

    let mut policy = WalletPolicy::from_str(descriptor_template)?;

    let key_info = KeyInfo {
        origin: Some((fingerprint, account_derivation)),
        xkey: xpub,
    };

    policy
        .set_key_info(vec![key_info])
        .map_err(WalletError::WalletPolicy)?;

    Ok(policy)
}

/// Errors constructing or encoding a Ledger wallet policy.
#[derive(Debug)]
pub enum WalletError {
    /// An invalid signature threshold.
    InvalidThreshold,
    /// A path purpose or address family not supported by the policy builder.
    UnsupportedAddressType,
    /// An invalid path, key, or policy.
    InvalidPolicy,
    /// A miniscript wallet policy error.
    WalletPolicy(
        /// Miniscript policy error.
        WalletPolicyError,
    ),
}

impl core::fmt::Display for WalletError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            WalletError::InvalidThreshold => write!(f, "invalid threshold"),
            WalletError::UnsupportedAddressType => write!(f, "unsupported address type"),
            WalletError::InvalidPolicy => write!(f, "invalid wallet policy"),
            WalletError::WalletPolicy(e) => write!(f, "wallet policy error: {e}"),
        }
    }
}

impl std::error::Error for WalletError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            WalletError::WalletPolicy(e) => Some(e),
            _ => None,
        }
    }
}

impl From<WalletPolicyError> for WalletError {
    fn from(e: WalletPolicyError) -> Self {
        WalletError::WalletPolicy(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wallet_serialize_v2() {
        let policy = WalletPolicy::from_str("wsh(sortedmulti(2,@0/**,@1/**))").unwrap();
        let wallet = LedgerWalletPolicy::new("Cold storage".to_string(), Version::V2, policy);
        // This will fail because into_descriptor requires key_info,
        // which is not set for a template-only policy.
        // The serialization should work once keys are provided via set_key_info.
        assert!(wallet.serialize().is_err());
    }

    #[test]
    fn test_singlesig_wallet_policy_p2tr() {
        use core::str::FromStr;
        let fg = Fingerprint::from_str("f5acc2fd").unwrap();
        let xpub = Xpub::from_str("tpubDCwYjpDhUdPGP5rS3wgNg13mTrrjBuG8V9VpWbyptX6TRPbNoZVXsoVUSkCjmQ8jJycjuDKBb9eataSymXakTTaGifxR6kmVsfFehH1ZgJT").unwrap();
        let path: DerivationPath = "m/86'/1'/0'/0/0".parse().unwrap();
        let policy = singlesig_wallet_policy(&path, fg, xpub).unwrap();
        let template = format!("{policy:#}");
        assert_eq!(template, "tr(@0/**)");
    }

    #[test]
    fn test_singlesig_wallet_policy_p2wpkh() {
        use core::str::FromStr;
        let fg = Fingerprint::from_str("f5acc2fd").unwrap();
        let xpub = Xpub::from_str("tpubDCwYjpDhUdPGP5rS3wgNg13mTrrjBuG8V9VpWbyptX6TRPbNoZVXsoVUSkCjmQ8jJycjuDKBb9eataSymXakTTaGifxR6kmVsfFehH1ZgJT").unwrap();
        let path: DerivationPath = "m/84'/1'/0'/0/0".parse().unwrap();
        let policy = singlesig_wallet_policy(&path, fg, xpub).unwrap();
        let template = format!("{policy:#}");
        assert_eq!(template, "wpkh(@0/**)");
    }
}
