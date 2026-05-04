//! LDK `KeysManager`-compatible derivation for auxiliary node key material.
//!
//! Matches `lightning::sign::KeysManager::new` hardened child indices 5, 6, and 7
//! from the same 32-byte master seed (BIP32 master from seed, then hardened children).

use bitcoin::bip32::{ChildNumber, Xpriv};
use bitcoin::secp256k1::Secp256k1;
use bitcoin::Network;

const INBOUND_PAYMENT_KEY_INDEX: ChildNumber = ChildNumber::Hardened { index: 5 };
const PEER_STORAGE_KEY_INDEX: ChildNumber = ChildNumber::Hardened { index: 6 };
const RECEIVE_AUTH_KEY_INDEX: ChildNumber = ChildNumber::Hardened { index: 7 };

/// Inbound payment, peer storage, and receive-auth key material (32 bytes each).
pub type LdkAuxiliaryKeysTriple = ([u8; 32], [u8; 32], [u8; 32]);

/// Derive the three 32-byte secrets LDK exposes via
/// [`NodeSigner::get_expanded_key`], [`NodeSigner::get_peer_storage_key`],
/// and [`NodeSigner::get_receive_auth_key`] for a [`lightning::sign::KeysManager`]
/// built from `seed`.
///
/// Network is ignored for non-serialized private derivation (same as LDK's `KeysManager::new`).
pub fn derive_ldk_keys_manager_auxiliary_secret_bytes(
    seed: &[u8; 32],
) -> Result<LdkAuxiliaryKeysTriple, bitcoin::bip32::Error> {
    let secp = Secp256k1::new();
    let master_key = Xpriv::new_master(Network::Bitcoin, seed)?;
    let inbound = master_key
        .derive_priv(&secp, &[INBOUND_PAYMENT_KEY_INDEX])?
        .private_key
        .secret_bytes();
    let peer = master_key
        .derive_priv(&secp, &[PEER_STORAGE_KEY_INDEX])?
        .private_key
        .secret_bytes();
    let recv = master_key
        .derive_priv(&secp, &[RECEIVE_AUTH_KEY_INDEX])?
        .private_key
        .secret_bytes();
    Ok((inbound, peer, recv))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auxiliary_triple_is_deterministic_and_distinct() {
        let seed = [42u8; 32];
        let (a, b, c) = derive_ldk_keys_manager_auxiliary_secret_bytes(&seed).unwrap();
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_ne!(b, c);
        let (a2, b2, c2) = derive_ldk_keys_manager_auxiliary_secret_bytes(&seed).unwrap();
        assert_eq!(a, a2);
        assert_eq!(b, b2);
        assert_eq!(c, c2);
    }
}
