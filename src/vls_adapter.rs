use crate::contract::{
    BootstrapData, ChannelOp, ChannelPublicKeys, ChannelRequest, ChannelResponse,
    DebugDerivedAddress, ExternalSignerBackend, NodeRequest, NodeResponse, SignerError,
    SignerRequest, SignerResponse, SpendableOutputUtxo, WalletInputMetadata,
};

#[cfg(feature = "with-vls")]
use crate::contract::SignerIdentity;

#[derive(Debug, thiserror::Error)]
pub enum VlsAdapterError {
    #[error("transport error: {0}")]
    Transport(String),
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("unsupported operation: {0}")]
    Unsupported(String),
}

impl From<VlsAdapterError> for SignerError {
    fn from(value: VlsAdapterError) -> Self {
        match value {
            VlsAdapterError::Transport(e) => SignerError::Transport(e),
            VlsAdapterError::Protocol(e) => SignerError::Protocol(e),
            VlsAdapterError::Unsupported(e) => SignerError::Unsupported(e),
        }
    }
}

/// Boundary trait isolating VLS dependency details behind a stable contract.
///
/// A concrete implementation in this crate can use vls-protocol-client types, but
/// RLN and sibling crates should only depend on this trait surface.
pub trait VlsClient: Send + Sync {
    fn bootstrap(&self) -> Result<BootstrapData, VlsAdapterError>;
    fn node_get_node_id(&self, recipient: String) -> Result<String, VlsAdapterError>;
    fn node_get_destination_script(
        &self,
        channel_keys_id_hex: String,
    ) -> Result<String, VlsAdapterError>;
    fn node_get_shutdown_scriptpubkey(&self) -> Result<String, VlsAdapterError>;
    fn node_get_secure_random_bytes(&self) -> Result<String, VlsAdapterError>;

    fn node_ecdh(
        &self,
        recipient: String,
        other_key: String,
        tweak: Option<String>,
    ) -> Result<String, VlsAdapterError>;

    fn node_sign_invoice(
        &self,
        hrp: String,
        u5bytes_hex: String,
    ) -> Result<(String, u8), VlsAdapterError>;

    fn node_sign_bolt12_invoice(&self, invoice: String) -> Result<String, VlsAdapterError>;

    fn node_sign_gossip_message(&self, message_hex: String) -> Result<String, VlsAdapterError>;

    fn node_sign_message(&self, message: String) -> Result<String, VlsAdapterError>;

    fn channel_generate_keys_id(
        &self,
        inbound: bool,
        channel_value_satoshis: u64,
        user_channel_id: u128,
    ) -> Result<String, VlsAdapterError>;

    fn channel_derive_signer(
        &self,
        channel_value_satoshis: u64,
        channel_keys_id_hex: String,
    ) -> Result<(String, ChannelPublicKeys), VlsAdapterError>;

    fn channel_read_signer(
        &self,
        channel_signer_state_hex: String,
    ) -> Result<(String, ChannelPublicKeys), VlsAdapterError>;

    fn channel_op(
        &self,
        channel_keys_id_hex: String,
        op: ChannelOp,
    ) -> Result<ChannelResponse, VlsAdapterError>;

    fn sign_spendable_outputs_psbt(
        &self,
        utxos: Vec<SpendableOutputUtxo>,
        psbt: String,
    ) -> Result<String, VlsAdapterError>;

    fn sign_rgb_psbt(
        &self,
        descriptors: Vec<String>,
        psbt: String,
    ) -> Result<String, VlsAdapterError>;

    fn get_wallet_input_metadata(
        &self,
        txid_hex: String,
        vout: u32,
        script_pubkey_hex: Option<String>,
        amount_sat: Option<u64>,
    ) -> Result<Option<WalletInputMetadata>, VlsAdapterError>;

    fn debug_derive_addresses(
        &self,
        script_pubkey_hex: String,
        max_index: u32,
    ) -> Result<Vec<DebugDerivedAddress>, VlsAdapterError>;
}

#[cfg(feature = "with-vls")]
pub mod vls_real {
    use super::*;
    use crate::contract::SpendableOutputUtxo;
    use base64::Engine;
    use bitcoin::bip32::{ChildNumber, DerivationPath, Fingerprint, Xpriv, Xpub};
    use bitcoin::psbt::Psbt;
    use bitcoin::secp256k1::ecdsa::Signature;
    use bitcoin::secp256k1::Secp256k1;
    use bitcoin::sighash::EcdsaSighashType;
    use bitcoin::Network;
    use bitcoin::Txid;
    use bitcoin::{Address, CompressedPublicKey, ScriptBuf};
    use lightning_signer::channel::CommitmentType;
    use serde::{Deserialize, Serialize};
    use std::str::FromStr;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    use vls_protocol::model::{Basepoints, BitcoinSignature, PubKey, Utxo};
    use vls_protocol::msgs::{
        Ecdh, EcdhReply, GetChannelBasepoints, GetChannelBasepointsReply, GetPerCommitmentPoint,
        GetPerCommitmentPoint2, GetPerCommitmentPoint2Reply, GetPerCommitmentPointReply, HsmdInit2,
        HsmdInit2Reply, NewChannel, NewChannelReply, SetupChannel, SetupChannelReply,
        SignCommitmentTxReply, SignCommitmentTxWithHtlcsReply, SignGossipMessage,
        SignGossipMessageReply, SignInvoice, SignInvoiceReply, SignLocalCommitmentTx2, SignMessage,
        SignMessageReply, SignRemoteCommitmentTx2, SignWithdrawal, SignWithdrawalReply,
        ValidateCommitmentTx2, ValidateCommitmentTxReply,
    };
    use vls_protocol::psbt::StreamedPSBT;
    use vls_protocol::serde_bolt::{Array, Octets, WireString};
    use vls_protocol_client::{call, node_call, Transport};
    use vls_protocol_signer::util::commitment_type_to_channel_type;

    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct ChannelState {
        dbid: u64,
        peer_id_hex: String,
        channel_value_satoshis: u64,
        channel_keys_id_hex: String,
        channel_pubkeys: ChannelPublicKeys,
    }

    fn to_bitcoin_sig(sig_hex: &str) -> Result<BitcoinSignature, VlsAdapterError> {
        let bytes = hex::decode(sig_hex)
            .map_err(|e| VlsAdapterError::Protocol(format!("invalid signature hex: {e}")))?;
        let sig = Signature::from_compact(&bytes)
            .or_else(|_| Signature::from_der(&bytes))
            .map_err(|e| VlsAdapterError::Protocol(format!("invalid signature bytes: {e}")))?;
        Ok(BitcoinSignature {
            signature: vls_protocol::model::Signature(sig.serialize_compact()),
            sighash: EcdsaSighashType::All as u8,
        })
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct WithdrawalUtxo {
        txid: String,
        outnum: u32,
        amount: u64,
        keyindex: u32,
        #[serde(default)]
        is_p2sh: bool,
        #[serde(default)]
        script_hex: String,
        #[serde(default)]
        is_in_coinbase: bool,
    }

    fn spendable_utxo_to_vls_model(u: SpendableOutputUtxo) -> Result<Utxo, VlsAdapterError> {
        let txid = Txid::from_str(&u.txid_hex).map_err(|e| {
            VlsAdapterError::Protocol(format!("invalid spendable utxo txid_hex: {e}"))
        })?;
        let script = if u.script_pubkey_hex.is_empty() {
            Octets::EMPTY
        } else {
            Octets(hex::decode(&u.script_pubkey_hex).map_err(|e| {
                VlsAdapterError::Protocol(format!("invalid spendable utxo script_pubkey_hex: {e}"))
            })?)
        };
        Ok(Utxo {
            txid,
            outnum: u.vout,
            amount: u.amount_sat,
            keyindex: u.keyindex,
            is_p2sh: u.is_p2sh,
            script,
            close_info: None,
            is_in_coinbase: u.is_in_coinbase,
        })
    }

    /// Real VLS-backed client shell.
    ///
    /// This keeps VLS dependency wiring isolated to this module while the rest of
    /// the crate exposes only contract types.
    pub struct RealVlsClient {
        transport: Arc<dyn Transport>,
        network: String,
        seed: Option<[u8; 32]>,
        next_dbid: AtomicU64,
    }

    impl RealVlsClient {
        // LDK starts from 2^48 - 1 and decrements commitment numbers.
        const LDK_INITIAL_COMMITMENT_NUMBER: u64 = (1u64 << 48) - 1;
        pub fn new(transport: Arc<dyn Transport>) -> Self {
            Self::new_with_network(transport, Network::Bitcoin.to_string())
        }

        pub fn new_with_network(transport: Arc<dyn Transport>, network: String) -> Self {
            Self::new_with_network_and_seed(transport, network, None)
        }

        pub fn new_with_network_and_seed(
            transport: Arc<dyn Transport>,
            network: String,
            seed: Option<[u8; 32]>,
        ) -> Self {
            Self {
                transport,
                network,
                seed,
                next_dbid: AtomicU64::new(1),
            }
        }

        pub fn transport(&self) -> Arc<dyn Transport> {
            Arc::clone(&self.transport)
        }

        pub fn network(&self) -> &str {
            &self.network
        }

        fn default_peer_id() -> [u8; 33] {
            [0u8; 33]
        }

        fn rgb_coin_type(network: Network, rgb: bool) -> u32 {
            match (network, rgb) {
                (Network::Bitcoin, true) => 827_166,
                (_, true) => 827_167,
                (Network::Bitcoin, false) => 0,
                _ => 1,
            }
        }

        fn rgb_account_derivation_path(network: Network, rgb: bool) -> DerivationPath {
            let coin_type = Self::rgb_coin_type(network, rgb);
            DerivationPath::from(vec![
                ChildNumber::from_hardened_idx(86).expect("valid purpose"),
                ChildNumber::from_hardened_idx(coin_type).expect("valid coin type"),
                ChildNumber::from_hardened_idx(0).expect("valid account"),
            ])
        }

        fn rgb_master_xpriv(seed: &[u8; 32], network: Network) -> Result<Xpriv, VlsAdapterError> {
            Xpriv::new_master(network, seed).map_err(|e| {
                VlsAdapterError::Protocol(format!("failed to derive rgb master xpriv: {e}"))
            })
        }

        fn rgb_account_xprv(
            seed: &[u8; 32],
            network: Network,
            rgb: bool,
        ) -> Result<(Xpriv, Fingerprint), VlsAdapterError> {
            let secp = Secp256k1::signing_only();
            let master = Self::rgb_master_xpriv(seed, network)?;
            let master_fingerprint = Xpub::from_priv(&secp, &master).fingerprint();
            let account = master
                .derive_priv(&secp, &Self::rgb_account_derivation_path(network, rgb))
                .map_err(|e| {
                    VlsAdapterError::Protocol(format!(
                        "failed to derive rgb account xpriv (rgb={rgb}): {e}"
                    ))
                })?;
            Ok((account, master_fingerprint))
        }

        fn rgb_account_xpubs_from_seed(
            seed: &[u8; 32],
            network: Network,
        ) -> Result<(Xpub, Xpub, Fingerprint), VlsAdapterError> {
            let secp = Secp256k1::signing_only();
            let (vanilla, master_fingerprint) = Self::rgb_account_xprv(seed, network, false)?;
            let (colored, _) = Self::rgb_account_xprv(seed, network, true)?;
            Ok((
                Xpub::from_priv(&secp, &vanilla),
                Xpub::from_priv(&secp, &colored),
                master_fingerprint,
            ))
        }

        fn dbid_to_channel_keys_id_hex(dbid: u64) -> String {
            let mut bytes = [0u8; 32];
            bytes[..8].copy_from_slice(&dbid.to_be_bytes());
            hex::encode(bytes)
        }

        fn channel_keys_id_hex_to_dbid(channel_keys_id_hex: &str) -> Result<u64, VlsAdapterError> {
            let bytes = hex::decode(channel_keys_id_hex).map_err(|e| {
                VlsAdapterError::Protocol(format!("invalid channel_keys_id hex: {e}"))
            })?;
            if bytes.len() != 32 {
                return Err(VlsAdapterError::Protocol(
                    "channel_keys_id must be 32 bytes".to_string(),
                ));
            }
            let mut dbid_bytes = [0u8; 8];
            dbid_bytes.copy_from_slice(&bytes[..8]);
            Ok(u64::from_be_bytes(dbid_bytes))
        }

        fn normalize_derivation_path(
            path: &bitcoin::bip32::DerivationPath,
        ) -> bitcoin::bip32::DerivationPath {
            let Some(last) = path.as_ref().last().copied() else {
                return bitcoin::bip32::DerivationPath::default();
            };
            bitcoin::bip32::DerivationPath::from(vec![last])
        }

        fn normalize_psbt_input_key_origins(psbt: &mut Psbt) {
            for input in &mut psbt.inputs {
                for (_, (_, (_, path))) in input.tap_key_origins.iter_mut() {
                    *path = Self::normalize_derivation_path(path);
                }
                for (_, (_, path)) in input.bip32_derivation.iter_mut() {
                    *path = Self::normalize_derivation_path(path);
                }
            }
        }

        fn utxos_from_psbt(&self, psbt: &Psbt) -> Result<Vec<Utxo>, VlsAdapterError> {
            let mut utxos = Vec::with_capacity(psbt.inputs.len());
            for (idx, input) in psbt.inputs.iter().enumerate() {
                let prevout = psbt
                    .unsigned_tx
                    .input
                    .get(idx)
                    .ok_or_else(|| {
                        VlsAdapterError::Protocol(format!(
                            "psbt input index {idx} missing matching unsigned tx input"
                        ))
                    })?
                    .previous_output;
                let witness_utxo = input.witness_utxo.as_ref().ok_or_else(|| {
                    VlsAdapterError::Protocol(format!(
                        "psbt input index {idx} missing witness_utxo"
                    ))
                })?;

                let keyindex_from_bip32 = input
                    .bip32_derivation
                    .values()
                    .next()
                    .and_then(|(_, path)| path.as_ref().last().copied())
                    .and_then(|cn| match cn {
                        ChildNumber::Normal { index } => Some(index),
                        ChildNumber::Hardened { .. } => None,
                    });
                let keyindex_from_tap = input
                    .tap_key_origins
                    .values()
                    .next()
                    .and_then(|(_, (_, path))| path.as_ref().last().copied())
                    .and_then(|cn| match cn {
                        ChildNumber::Normal { index } => Some(index),
                        ChildNumber::Hardened { .. } => None,
                    });
                let keyindex = keyindex_from_bip32.or(keyindex_from_tap).unwrap_or(
                    self.infer_keyindex_from_script(&witness_utxo.script_pubkey)?
                        .unwrap_or(0),
                );

                utxos.push(Utxo {
                    txid: prevout.txid,
                    outnum: prevout.vout,
                    amount: witness_utxo.value.to_sat(),
                    keyindex,
                    is_p2sh: false,
                    script: Octets(witness_utxo.script_pubkey.as_bytes().to_vec()),
                    close_info: None,
                    is_in_coinbase: false,
                });
            }
            Ok(utxos)
        }

        fn infer_keyindex_from_script(
            &self,
            script: &bitcoin::ScriptBuf,
        ) -> Result<Option<u32>, VlsAdapterError> {
            let bootstrap = self.bootstrap()?;
            let network = Network::from_str(self.network()).map_err(|e| {
                VlsAdapterError::Protocol(format!("invalid network in adapter: {e}"))
            })?;
            let account_xpub_colored = Xpub::from_str(&bootstrap.identity.account_xpub_colored)
                .map_err(|e| {
                    VlsAdapterError::Protocol(format!("invalid bootstrap colored xpub: {e}"))
                })?;
            let account_xpub_vanilla = Xpub::from_str(&bootstrap.identity.account_xpub_vanilla)
                .map_err(|e| {
                    VlsAdapterError::Protocol(format!("invalid bootstrap vanilla xpub: {e}"))
                })?;
            let secp = Secp256k1::verification_only();
            let candidates = [account_xpub_colored, account_xpub_vanilla];
            for idx in 0u32..10_000 {
                let idx_child = ChildNumber::from_normal_idx(idx)
                    .map_err(|e| VlsAdapterError::Protocol(format!("invalid child index: {e}")))?;
                for base_xpub in candidates {
                    // Legacy one-level account child: /idx
                    let one_level = base_xpub.derive_pub(&secp, &[idx_child]).map_err(|e| {
                        VlsAdapterError::Protocol(format!("xpub derive failed: {e}"))
                    })?;
                    let one_level_cpk =
                        CompressedPublicKey::from_slice(&one_level.public_key.serialize())
                            .map_err(|e| {
                                VlsAdapterError::Protocol(format!("invalid derived pubkey: {e}"))
                            })?;
                    let p2wpkh = Address::p2wpkh(&one_level_cpk, network).script_pubkey();
                    if &p2wpkh == script {
                        return Ok(Some(idx));
                    }
                    let (xonly, _) = one_level.public_key.x_only_public_key();
                    let p2tr = Address::p2tr(&secp, xonly, None, network).script_pubkey();
                    if &p2tr == script {
                        return Ok(Some(idx));
                    }

                    // BIP86/BIP84 style branch paths: /0/idx and /1/idx.
                    for branch in [0u32, 1u32] {
                        let branch_child = ChildNumber::from_normal_idx(branch).map_err(|e| {
                            VlsAdapterError::Protocol(format!("invalid branch index: {e}"))
                        })?;
                        let child = base_xpub
                            .derive_pub(&secp, &[branch_child, idx_child])
                            .map_err(|e| {
                                VlsAdapterError::Protocol(format!("xpub derive failed: {e}"))
                            })?;
                        let cpk = CompressedPublicKey::from_slice(&child.public_key.serialize())
                            .map_err(|e| {
                                VlsAdapterError::Protocol(format!("invalid derived pubkey: {e}"))
                            })?;
                        let p2wpkh = Address::p2wpkh(&cpk, network).script_pubkey();
                        if &p2wpkh == script {
                            return Ok(Some(idx));
                        }
                        let (xonly, _) = child.public_key.x_only_public_key();
                        let p2tr = Address::p2tr(&secp, xonly, None, network).script_pubkey();
                        if &p2tr == script {
                            return Ok(Some(idx));
                        }
                    }
                }
            }
            Ok(None)
        }

        fn derive_absolute_paths_for_script_and_index(
            &self,
            script: &bitcoin::ScriptBuf,
            keyindex: u32,
        ) -> Result<Vec<bitcoin::bip32::DerivationPath>, VlsAdapterError> {
            let bootstrap = self.bootstrap()?;
            let network = Network::from_str(self.network()).map_err(|e| {
                VlsAdapterError::Protocol(format!("invalid network in adapter: {e}"))
            })?;
            let account_xpub_colored = Xpub::from_str(&bootstrap.identity.account_xpub_colored)
                .map_err(|e| {
                    VlsAdapterError::Protocol(format!("invalid bootstrap colored xpub: {e}"))
                })?;
            let account_xpub_vanilla = Xpub::from_str(&bootstrap.identity.account_xpub_vanilla)
                .map_err(|e| {
                    VlsAdapterError::Protocol(format!("invalid bootstrap vanilla xpub: {e}"))
                })?;
            let secp = Secp256k1::verification_only();
            let idx_child = ChildNumber::from_normal_idx(keyindex)
                .map_err(|e| VlsAdapterError::Protocol(format!("invalid child index: {e}")))?;
            let colored_prefix = ChildNumber::from_normal_idx(1).map_err(|e| {
                VlsAdapterError::Protocol(format!("invalid colored account index: {e}"))
            })?;
            let candidates = [
                (Vec::<ChildNumber>::new(), account_xpub_vanilla),
                (vec![colored_prefix], account_xpub_colored),
            ];
            let mut out = Vec::new();
            for (prefix, base_xpub) in candidates {
                let one_level = base_xpub
                    .derive_pub(&secp, &[idx_child])
                    .map_err(|e| VlsAdapterError::Protocol(format!("xpub derive failed: {e}")))?;
                let one_level_cpk = CompressedPublicKey::from_slice(
                    &one_level.public_key.serialize(),
                )
                .map_err(|e| VlsAdapterError::Protocol(format!("invalid derived pubkey: {e}")))?;
                let one_level_p2wpkh = Address::p2wpkh(&one_level_cpk, network).script_pubkey();
                let (one_level_xonly, _) = one_level.public_key.x_only_public_key();
                let one_level_p2tr =
                    Address::p2tr(&secp, one_level_xonly, None, network).script_pubkey();
                if &one_level_p2wpkh == script || &one_level_p2tr == script {
                    let mut path = prefix.clone();
                    path.push(idx_child);
                    out.push(bitcoin::bip32::DerivationPath::from(path));
                }
                for branch in [0u32, 1u32] {
                    let branch_child = ChildNumber::from_normal_idx(branch).map_err(|e| {
                        VlsAdapterError::Protocol(format!("invalid branch index: {e}"))
                    })?;
                    let child = base_xpub
                        .derive_pub(&secp, &[branch_child, idx_child])
                        .map_err(|e| {
                            VlsAdapterError::Protocol(format!("xpub derive failed: {e}"))
                        })?;
                    let cpk = CompressedPublicKey::from_slice(&child.public_key.serialize())
                        .map_err(|e| {
                            VlsAdapterError::Protocol(format!("invalid derived pubkey: {e}"))
                        })?;
                    let p2wpkh = Address::p2wpkh(&cpk, network).script_pubkey();
                    let (xonly, _) = child.public_key.x_only_public_key();
                    let p2tr = Address::p2tr(&secp, xonly, None, network).script_pubkey();
                    if &p2wpkh == script || &p2tr == script {
                        let mut path = prefix.clone();
                        path.push(branch_child);
                        path.push(idx_child);
                        out.push(bitcoin::bip32::DerivationPath::from(path));
                    }
                }
            }
            Ok(out)
        }

        fn rewrite_output_key_origins_for_vls(
            &self,
            psbt: &mut Psbt,
        ) -> Result<(), VlsAdapterError> {
            for (idx, output) in psbt.outputs.iter_mut().enumerate() {
                let script = psbt
                    .unsigned_tx
                    .output
                    .get(idx)
                    .ok_or_else(|| {
                        VlsAdapterError::Protocol(format!(
                            "psbt output index {idx} missing matching unsigned tx output"
                        ))
                    })?
                    .script_pubkey
                    .clone();
                let keyindex = output
                    .tap_key_origins
                    .values()
                    .next()
                    .and_then(|(_, (_, path))| path.as_ref().last().copied())
                    .or_else(|| {
                        output
                            .bip32_derivation
                            .values()
                            .next()
                            .and_then(|(_, path)| path.as_ref().last().copied())
                    })
                    .and_then(|cn| match cn {
                        ChildNumber::Normal { index } => Some(index),
                        ChildNumber::Hardened { .. } => None,
                    });
                let Some(keyindex) = keyindex else {
                    continue;
                };
                let absolute_paths =
                    self.derive_absolute_paths_for_script_and_index(&script, keyindex)?;
                if absolute_paths.is_empty() {
                    return Err(VlsAdapterError::Protocol(format!(
                        "psbt output script {} with keyindex {} is not derivable from signer bootstrap xpubs",
                        hex::encode(script.as_bytes()),
                        keyindex,
                    )));
                }
                if absolute_paths.len() != 1 {
                    continue;
                }
                let absolute_path = absolute_paths[0].clone();
                for (_, (_, (_, path))) in output.tap_key_origins.iter_mut() {
                    *path = absolute_path.clone();
                }
                for (_, (_, path)) in output.bip32_derivation.iter_mut() {
                    *path = absolute_path.clone();
                }
            }
            Ok(())
        }

        fn derive_matches_for_script(
            &self,
            script: &bitcoin::ScriptBuf,
            max_index: u32,
        ) -> Result<Vec<DebugDerivedAddress>, VlsAdapterError> {
            let bootstrap = self.bootstrap()?;
            let network = Network::from_str(self.network()).map_err(|e| {
                VlsAdapterError::Protocol(format!("invalid network in adapter: {e}"))
            })?;
            let account_xpub_colored = Xpub::from_str(&bootstrap.identity.account_xpub_colored)
                .map_err(|e| {
                    VlsAdapterError::Protocol(format!("invalid bootstrap colored xpub: {e}"))
                })?;
            let account_xpub_vanilla = Xpub::from_str(&bootstrap.identity.account_xpub_vanilla)
                .map_err(|e| {
                    VlsAdapterError::Protocol(format!("invalid bootstrap vanilla xpub: {e}"))
                })?;
            let secp = Secp256k1::verification_only();
            let mut out = Vec::new();
            let candidates = [
                ("colored", account_xpub_colored),
                ("vanilla", account_xpub_vanilla),
            ];
            for idx in 0..=max_index {
                let idx_child = ChildNumber::from_normal_idx(idx)
                    .map_err(|e| VlsAdapterError::Protocol(format!("invalid child index: {e}")))?;
                for (account_name, base_xpub) in candidates {
                    let one_level = base_xpub.derive_pub(&secp, &[idx_child]).map_err(|e| {
                        VlsAdapterError::Protocol(format!("xpub derive failed: {e}"))
                    })?;
                    let one_level_cpk =
                        CompressedPublicKey::from_slice(&one_level.public_key.serialize())
                            .map_err(|e| {
                                VlsAdapterError::Protocol(format!("invalid derived pubkey: {e}"))
                            })?;
                    let one_level_p2wpkh = Address::p2wpkh(&one_level_cpk, network);
                    if one_level_p2wpkh.script_pubkey() == *script {
                        out.push(DebugDerivedAddress {
                            keyindex: idx,
                            address: one_level_p2wpkh.to_string(),
                            derivation: format!("{idx}"),
                            account: account_name.to_string(),
                        });
                    }
                    let (one_level_xonly, _) = one_level.public_key.x_only_public_key();
                    let one_level_p2tr = Address::p2tr(&secp, one_level_xonly, None, network);
                    if one_level_p2tr.script_pubkey() == *script {
                        out.push(DebugDerivedAddress {
                            keyindex: idx,
                            address: one_level_p2tr.to_string(),
                            derivation: format!("{idx}"),
                            account: account_name.to_string(),
                        });
                    }
                    for branch in [0u32, 1u32] {
                        let branch_child = ChildNumber::from_normal_idx(branch).map_err(|e| {
                            VlsAdapterError::Protocol(format!("invalid branch index: {e}"))
                        })?;
                        let child = base_xpub
                            .derive_pub(&secp, &[branch_child, idx_child])
                            .map_err(|e| {
                                VlsAdapterError::Protocol(format!("xpub derive failed: {e}"))
                            })?;
                        let cpk = CompressedPublicKey::from_slice(&child.public_key.serialize())
                            .map_err(|e| {
                                VlsAdapterError::Protocol(format!("invalid derived pubkey: {e}"))
                            })?;
                        let p2wpkh = Address::p2wpkh(&cpk, network);
                        if p2wpkh.script_pubkey() == *script {
                            out.push(DebugDerivedAddress {
                                keyindex: idx,
                                address: p2wpkh.to_string(),
                                derivation: format!("{branch}/{idx}"),
                                account: account_name.to_string(),
                            });
                        }
                        let (xonly, _) = child.public_key.x_only_public_key();
                        let p2tr = Address::p2tr(&secp, xonly, None, network);
                        if p2tr.script_pubkey() == *script {
                            out.push(DebugDerivedAddress {
                                keyindex: idx,
                                address: p2tr.to_string(),
                                derivation: format!("{branch}/{idx}"),
                                account: account_name.to_string(),
                            });
                        }
                    }
                }
            }
            Ok(out)
        }

        fn sign_withdrawal_with_utxos(
            &self,
            utxos: Vec<Utxo>,
            psbt_obj: Psbt,
        ) -> Result<String, VlsAdapterError> {
            let streamed_psbt = StreamedPSBT::new(psbt_obj).into();
            let reply: SignWithdrawalReply = node_call(
                &*self.transport,
                SignWithdrawal {
                    utxos: Array(utxos),
                    psbt: streamed_psbt,
                },
            )
            .map_err(|e| VlsAdapterError::Transport(format!("sign_withdrawal failed: {e:?}")))?;
            Ok(base64::engine::general_purpose::STANDARD.encode(reply.psbt.0.inner.serialize()))
        }

        fn derive_one_level_taproot_script_for_keyindex(
            &self,
            keyindex: u32,
        ) -> Result<Octets, VlsAdapterError> {
            let bootstrap = self.bootstrap()?;
            let network = Network::from_str(self.network()).map_err(|e| {
                VlsAdapterError::Protocol(format!("invalid network in adapter: {e}"))
            })?;
            let xpub = Xpub::from_str(&bootstrap.identity.account_xpub_vanilla).map_err(|e| {
                VlsAdapterError::Protocol(format!("invalid bootstrap vanilla xpub: {e}"))
            })?;
            let secp = Secp256k1::verification_only();
            let child = xpub
                .derive_pub(
                    &secp,
                    &[ChildNumber::from_normal_idx(keyindex).map_err(|e| {
                        VlsAdapterError::Protocol(format!("invalid child index: {e}"))
                    })?],
                )
                .map_err(|e| VlsAdapterError::Protocol(format!("xpub derive failed: {e}")))?;
            let (xonly, _) = child.public_key.x_only_public_key();
            let script = Address::p2tr(&secp, xonly, None, network).script_pubkey();
            Ok(Octets(script.as_bytes().to_vec()))
        }

        fn get_channel_pubkeys(
            &self,
            dbid: u64,
            peer_id: [u8; 33],
        ) -> Result<ChannelPublicKeys, VlsAdapterError> {
            let reply: GetChannelBasepointsReply = call(
                dbid,
                PubKey(peer_id),
                &*self.transport,
                GetChannelBasepoints {
                    node_id: PubKey(peer_id),
                    dbid,
                },
            )
            .map_err(|e| {
                VlsAdapterError::Transport(format!("get_channel_basepoints failed: {e:?}"))
            })?;

            Ok(ChannelPublicKeys {
                funding_pubkey_hex: hex::encode(reply.funding.0),
                revocation_basepoint_hex: hex::encode(reply.basepoints.revocation.0),
                payment_point_hex: hex::encode(reply.basepoints.payment.0),
                delayed_payment_basepoint_hex: hex::encode(reply.basepoints.delayed_payment.0),
                htlc_basepoint_hex: hex::encode(reply.basepoints.htlc.0),
            })
        }

        fn derive_native_script_hex(&self, child_index: u32) -> Result<String, VlsAdapterError> {
            let bootstrap = self.bootstrap()?;
            let network = Network::from_str(self.network()).map_err(|e| {
                VlsAdapterError::Protocol(format!("invalid network in adapter: {e}"))
            })?;
            let xpub = Xpub::from_str(&bootstrap.identity.account_xpub_colored)
                .map_err(|e| VlsAdapterError::Protocol(format!("invalid bootstrap xpub: {e}")))?;
            let secp = Secp256k1::verification_only();
            let child = xpub
                .derive_pub(
                    &secp,
                    &[ChildNumber::from_normal_idx(child_index).map_err(|e| {
                        VlsAdapterError::Protocol(format!("invalid child index: {e}"))
                    })?],
                )
                .map_err(|e| VlsAdapterError::Protocol(format!("xpub derive failed: {e}")))?;
            let compressed = CompressedPublicKey::from_slice(&child.public_key.serialize())
                .map_err(|e| VlsAdapterError::Protocol(format!("invalid child pubkey: {e}")))?;
            let script: ScriptBuf = Address::p2wpkh(&compressed, network).script_pubkey();
            Ok(hex::encode(script.as_bytes()))
        }
    }

    impl VlsClient for RealVlsClient {
        fn bootstrap(&self) -> Result<BootstrapData, VlsAdapterError> {
            let init_message = HsmdInit2 {
                derivation_style: 2, // Ldk
                network_name: WireString(self.network().as_bytes().to_vec()),
                dev_seed: None,
                dev_allowlist: Array::new(),
            };

            let reply: HsmdInit2Reply = node_call(&*self.transport, init_message)
                .map_err(|e| VlsAdapterError::Transport(format!("HsmdInit2 failed: {e:?}")))?;

            let xpub = Xpub::decode(&reply.bip32.0).map_err(|e| {
                VlsAdapterError::Protocol(format!("invalid xpub in HsmdInit2: {e}"))
            })?;
            let node_id = hex::encode(reply.node_id.0);
            let network = Network::from_str(self.network()).map_err(|e| {
                VlsAdapterError::Protocol(format!("invalid network in adapter: {e}"))
            })?;
            let (xpub_vanilla, xpub_colored, master_fingerprint) = if let Some(seed) = self.seed {
                let (vanilla, colored, fingerprint) =
                    Self::rgb_account_xpubs_from_seed(&seed, network)?;
                (
                    vanilla.to_string(),
                    colored.to_string(),
                    fingerprint.to_string(),
                )
            } else {
                (
                    xpub.to_string(),
                    xpub.to_string(),
                    xpub.fingerprint().to_string(),
                )
            };

            let seed = self.seed.ok_or_else(|| {
                VlsAdapterError::Protocol(
                    "RealVlsClient requires Some(seed) in new_with_network_and_seed so bootstrap can export LDK inbound/peer_storage/receive_auth key material".into(),
                )
            })?;
            let (a, b, c) =
                crate::ldk_keys_manager_material::derive_ldk_keys_manager_auxiliary_secret_bytes(
                    &seed,
                )
                .map_err(|e| {
                    VlsAdapterError::Protocol(format!("derive LDK auxiliary keys: {e}"))
                })?;
            let ldk_inbound_payment_key_hex = hex::encode(a);
            let ldk_peer_storage_key_hex = hex::encode(b);
            let ldk_receive_auth_key_hex = hex::encode(c);

            Ok(BootstrapData {
                identity: SignerIdentity {
                    node_id,
                    account_xpub_vanilla: xpub_vanilla,
                    account_xpub_colored: xpub_colored,
                    master_fingerprint,
                },
                protocol_version: "vls-protocol/0.14".to_string(),
                api_level: 1,
                ldk_inbound_payment_key_hex,
                ldk_peer_storage_key_hex,
                ldk_receive_auth_key_hex,
                async_payments_root_seed_hex: hex::encode(seed),
            })
        }

        fn node_get_node_id(&self, recipient: String) -> Result<String, VlsAdapterError> {
            if recipient != "node" {
                return Err(VlsAdapterError::Unsupported(format!(
                    "unsupported recipient for get_node_id: {recipient}"
                )));
            }
            Ok(self.bootstrap()?.identity.node_id)
        }

        fn node_get_destination_script(
            &self,
            channel_keys_id_hex: String,
        ) -> Result<String, VlsAdapterError> {
            let dbid = Self::channel_keys_id_hex_to_dbid(&channel_keys_id_hex)?;
            self.derive_native_script_hex(dbid as u32)
        }

        fn node_get_shutdown_scriptpubkey(&self) -> Result<String, VlsAdapterError> {
            self.derive_native_script_hex(0)
        }

        fn node_get_secure_random_bytes(&self) -> Result<String, VlsAdapterError> {
            Ok(hex::encode([0u8; 32]))
        }

        fn node_ecdh(
            &self,
            recipient: String,
            other_key: String,
            tweak: Option<String>,
        ) -> Result<String, VlsAdapterError> {
            if recipient != "node" {
                return Err(VlsAdapterError::Unsupported(format!(
                    "unsupported recipient for ecdh: {recipient}"
                )));
            }
            if tweak.is_some() {
                return Err(VlsAdapterError::Unsupported(
                    "ecdh tweak is not supported by current VLS adapter".to_string(),
                ));
            }

            let point_bytes = hex::decode(other_key).map_err(|e| {
                VlsAdapterError::Protocol(format!("invalid other_key hex for ecdh: {e}"))
            })?;
            let point: [u8; 33] = point_bytes.try_into().map_err(|_| {
                VlsAdapterError::Protocol(
                    "ecdh other_key must be 33-byte compressed pubkey".to_string(),
                )
            })?;

            let reply: EcdhReply = node_call(
                &*self.transport,
                Ecdh {
                    point: PubKey(point),
                },
            )
            .map_err(|e| VlsAdapterError::Transport(format!("ecdh failed: {e:?}")))?;
            Ok(hex::encode(reply.secret.0))
        }

        fn node_sign_invoice(
            &self,
            hrp: String,
            u5bytes_hex: String,
        ) -> Result<(String, u8), VlsAdapterError> {
            let u5bytes = hex::decode(u5bytes_hex).map_err(|e| {
                VlsAdapterError::Protocol(format!("invalid invoice u5bytes hex: {e}"))
            })?;
            let reply: SignInvoiceReply = node_call(
                &*self.transport,
                SignInvoice {
                    u5bytes: Octets(u5bytes),
                    hrp: Octets(hrp.into_bytes()),
                },
            )
            .map_err(|e| VlsAdapterError::Transport(format!("sign_invoice failed: {e:?}")))?;
            let sig = reply.signature.0;
            Ok((hex::encode(&sig[..64]), sig[64]))
        }

        fn node_sign_bolt12_invoice(&self, _invoice: String) -> Result<String, VlsAdapterError> {
            Err(VlsAdapterError::Unsupported(
                "node_sign_bolt12_invoice requires structured BOLT12 payload mapping".to_string(),
            ))
        }

        fn node_sign_gossip_message(&self, message_hex: String) -> Result<String, VlsAdapterError> {
            let message = hex::decode(message_hex).map_err(|e| {
                VlsAdapterError::Protocol(format!("invalid gossip message hex: {e}"))
            })?;
            let reply: SignGossipMessageReply = node_call(
                &*self.transport,
                SignGossipMessage {
                    message: Octets(message),
                },
            )
            .map_err(|e| {
                VlsAdapterError::Transport(format!("sign_gossip_message failed: {e:?}"))
            })?;
            Ok(hex::encode(reply.signature.0))
        }

        fn node_sign_message(&self, message: String) -> Result<String, VlsAdapterError> {
            let reply: SignMessageReply = node_call(
                &*self.transport,
                SignMessage {
                    message: Octets(message.into_bytes()),
                },
            )
            .map_err(|e| VlsAdapterError::Transport(format!("sign_message failed: {e:?}")))?;
            Ok(hex::encode(reply.signature.0))
        }

        fn channel_generate_keys_id(
            &self,
            _inbound: bool,
            _channel_value_satoshis: u64,
            _user_channel_id: u128,
        ) -> Result<String, VlsAdapterError> {
            let dbid = self.next_dbid.fetch_add(1, Ordering::AcqRel);
            Ok(Self::dbid_to_channel_keys_id_hex(dbid))
        }

        fn channel_derive_signer(
            &self,
            channel_value_satoshis: u64,
            channel_keys_id_hex: String,
        ) -> Result<(String, ChannelPublicKeys), VlsAdapterError> {
            let dbid = Self::channel_keys_id_hex_to_dbid(&channel_keys_id_hex)?;
            let peer_id = Self::default_peer_id();
            tracing::debug!(
                dbid,
                peer_id = %hex::encode(peer_id),
                "external signer derive_channel_signer"
            );

            let _: NewChannelReply = call(
                dbid,
                PubKey(peer_id),
                &*self.transport,
                NewChannel {
                    peer_id: PubKey(peer_id),
                    dbid,
                },
            )
            .map_err(|e| VlsAdapterError::Transport(format!("new_channel failed: {e:?}")))?;

            let channel_pubkeys = self.get_channel_pubkeys(dbid, peer_id)?;
            let state = ChannelState {
                dbid,
                peer_id_hex: hex::encode(peer_id),
                channel_value_satoshis,
                channel_keys_id_hex,
                channel_pubkeys: channel_pubkeys.clone(),
            };
            let state_hex = hex::encode(serde_json::to_vec(&state).map_err(|e| {
                VlsAdapterError::Protocol(format!("serialize channel state failed: {e}"))
            })?);

            Ok((state_hex, channel_pubkeys))
        }

        fn channel_read_signer(
            &self,
            channel_signer_state_hex: String,
        ) -> Result<(String, ChannelPublicKeys), VlsAdapterError> {
            let state_bytes = hex::decode(channel_signer_state_hex.as_str()).map_err(|e| {
                VlsAdapterError::Protocol(format!("invalid channel_signer_state hex: {e}"))
            })?;
            let state: ChannelState = serde_json::from_slice(&state_bytes).map_err(|e| {
                VlsAdapterError::Protocol(format!("invalid channel_signer_state json: {e}"))
            })?;
            Ok((channel_signer_state_hex, state.channel_pubkeys))
        }

        fn channel_op(
            &self,
            channel_keys_id_hex: String,
            op: ChannelOp,
        ) -> Result<ChannelResponse, VlsAdapterError> {
            let dbid = Self::channel_keys_id_hex_to_dbid(&channel_keys_id_hex)?;
            let peer_id = Self::default_peer_id();

            match op {
                ChannelOp::SetupChannel {
                    is_outbound,
                    channel_value_satoshis,
                    push_value_msat,
                    funding_txid_hex,
                    funding_vout,
                    holder_selected_contest_delay,
                    counterparty_pubkeys,
                    counterparty_selected_contest_delay,
                    channel_type_kind,
                } => {
                    tracing::debug!(
                        dbid,
                        peer_id = %hex::encode(peer_id),
                        funding_txid = %funding_txid_hex,
                        funding_vout,
                        "external signer setup_channel"
                    );
                    let funding_txid = Txid::from_str(&funding_txid_hex).map_err(|e| {
                        VlsAdapterError::Protocol(format!("invalid funding_txid_hex: {e}"))
                    })?;
                    let funding_pubkey = hex::decode(&counterparty_pubkeys.funding_pubkey_hex)
                        .map_err(|e| {
                            VlsAdapterError::Protocol(format!(
                                "invalid counterparty funding_pubkey_hex: {e}"
                            ))
                        })?;
                    let funding_pubkey: [u8; 33] = funding_pubkey.try_into().map_err(|_| {
                        VlsAdapterError::Protocol(
                            "counterparty funding_pubkey must be 33 bytes".to_string(),
                        )
                    })?;
                    let decode_basepoint =
                        |name: &str, value: &str| -> Result<[u8; 33], VlsAdapterError> {
                            let bytes = hex::decode(value).map_err(|e| {
                                VlsAdapterError::Protocol(format!(
                                    "invalid counterparty {name}: {e}"
                                ))
                            })?;
                            bytes.try_into().map_err(|_| {
                                VlsAdapterError::Protocol(format!(
                                    "counterparty {name} must be 33 bytes"
                                ))
                            })
                        };
                    let remote_basepoints = Basepoints {
                        revocation: PubKey(decode_basepoint(
                            "revocation_basepoint_hex",
                            &counterparty_pubkeys.revocation_basepoint_hex,
                        )?),
                        payment: PubKey(decode_basepoint(
                            "payment_point_hex",
                            &counterparty_pubkeys.payment_point_hex,
                        )?),
                        htlc: PubKey(decode_basepoint(
                            "htlc_basepoint_hex",
                            &counterparty_pubkeys.htlc_basepoint_hex,
                        )?),
                        delayed_payment: PubKey(decode_basepoint(
                            "delayed_payment_basepoint_hex",
                            &counterparty_pubkeys.delayed_payment_basepoint_hex,
                        )?),
                    };
                    let commitment_type = match channel_type_kind {
                        2 => CommitmentType::AnchorsZeroFeeHtlc,
                        1 => CommitmentType::Anchors,
                        _ => CommitmentType::StaticRemoteKey,
                    };
                    let channel_type = commitment_type_to_channel_type(commitment_type);
                    let _: SetupChannelReply = call(
                        dbid,
                        PubKey(peer_id),
                        &*self.transport,
                        SetupChannel {
                            is_outbound,
                            channel_value: channel_value_satoshis,
                            push_value: push_value_msat,
                            funding_txid,
                            funding_txout: funding_vout,
                            to_self_delay: holder_selected_contest_delay,
                            local_shutdown_script: Octets::EMPTY,
                            local_shutdown_wallet_index: None,
                            remote_basepoints,
                            remote_funding_pubkey: PubKey(funding_pubkey),
                            remote_to_self_delay: counterparty_selected_contest_delay,
                            remote_shutdown_script: Octets::EMPTY,
                            channel_type: Octets(channel_type),
                        },
                    )
                    .map_err(|e| {
                        VlsAdapterError::Transport(format!("setup_channel failed: {e:?}"))
                    })?;
                    Ok(ChannelResponse::SetupComplete)
                }
                ChannelOp::GetPerCommitmentPoint { idx } => {
                    let commitment_number = Self::LDK_INITIAL_COMMITMENT_NUMBER.saturating_sub(idx);
                    let reply: GetPerCommitmentPoint2Reply = call(
                        dbid,
                        PubKey(peer_id),
                        &*self.transport,
                        GetPerCommitmentPoint2 { commitment_number },
                    )
                    .map_err(|e| {
                        VlsAdapterError::Transport(format!(
                            "get_per_commitment_point failed: {e:?}"
                        ))
                    })?;
                    Ok(ChannelResponse::PerCommitmentPoint {
                        point_hex: hex::encode(reply.point.0),
                    })
                }
                ChannelOp::ReleaseCommitmentSecret { idx } => {
                    let commitment_number = Self::LDK_INITIAL_COMMITMENT_NUMBER
                        .saturating_sub(idx)
                        .saturating_add(2);
                    let reply: GetPerCommitmentPointReply = call(
                        dbid,
                        PubKey(peer_id),
                        &*self.transport,
                        GetPerCommitmentPoint { commitment_number },
                    )
                    .map_err(|e| {
                        VlsAdapterError::Transport(format!(
                            "release_commitment_secret failed: {e:?}"
                        ))
                    })?;
                    let Some(secret) = reply.secret else {
                        return Err(VlsAdapterError::Protocol(
                            "VLS did not return revocation secret".to_string(),
                        ));
                    };
                    Ok(ChannelResponse::CommitmentSecret {
                        secret_hex: hex::encode(secret.0),
                    })
                }
                ChannelOp::ValidateHolderCommitment {
                    commitment_number,
                    feerate_sat_per_kw,
                    to_local_value_sat,
                    to_remote_value_sat,
                    htlcs,
                    counterparty_signature_hex,
                    counterparty_htlc_signatures_hex,
                } => {
                    let htlcs = Array(
                        htlcs
                            .into_iter()
                            .map(|h| {
                                let payment_hash =
                                    hex::decode(&h.payment_hash_hex).map_err(|e| {
                                        VlsAdapterError::Protocol(format!(
                                            "invalid payment_hash_hex: {e}"
                                        ))
                                    })?;
                                let payment_hash: [u8; 32] =
                                    payment_hash.try_into().map_err(|_| {
                                        VlsAdapterError::Protocol(
                                            "payment_hash must be 32 bytes".to_string(),
                                        )
                                    })?;
                                Ok(vls_protocol::model::Htlc {
                                    side: h.side,
                                    amount: h.amount_msat,
                                    payment_hash: vls_protocol::model::Sha256(payment_hash),
                                    ctlv_expiry: h.cltv_expiry,
                                })
                            })
                            .collect::<Result<Vec<_>, VlsAdapterError>>()?,
                    );
                    let signature = to_bitcoin_sig(&counterparty_signature_hex)?;
                    let htlc_signatures = Array(
                        counterparty_htlc_signatures_hex
                            .iter()
                            .map(|s| to_bitcoin_sig(s))
                            .collect::<Result<Vec<_>, VlsAdapterError>>()?,
                    );
                    let _: ValidateCommitmentTxReply = call(
                        dbid,
                        PubKey(peer_id),
                        &*self.transport,
                        ValidateCommitmentTx2 {
                            commitment_number,
                            feerate: feerate_sat_per_kw,
                            to_local_value_sat,
                            to_remote_value_sat,
                            htlcs,
                            signature,
                            htlc_signatures,
                        },
                    )
                    .map_err(|e| {
                        VlsAdapterError::Transport(format!(
                            "validate_holder_commitment failed: {e:?}"
                        ))
                    })?;
                    Ok(ChannelResponse::ValidationComplete)
                }
                ChannelOp::SignHolderCommitment {
                    commitment_number, ..
                } => {
                    let reply: SignCommitmentTxReply = call(
                        dbid,
                        PubKey(peer_id),
                        &*self.transport,
                        SignLocalCommitmentTx2 { commitment_number },
                    )
                    .map_err(|e| {
                        VlsAdapterError::Transport(format!("sign_holder_commitment failed: {e:?}"))
                    })?;
                    Ok(ChannelResponse::Signature {
                        signature_hex: hex::encode(reply.signature.signature.0),
                    })
                }
                ChannelOp::SignCounterpartyCommitment {
                    remote_per_commitment_point_hex,
                    commitment_number,
                    feerate_sat_per_kw,
                    to_local_value_sat,
                    to_remote_value_sat,
                    htlcs,
                    ..
                } => {
                    tracing::debug!(
                        dbid,
                        peer_id = %hex::encode(peer_id),
                        commitment_number,
                        "external signer sign_counterparty_commitment"
                    );
                    let remote_per_commitment_point = hex::decode(&remote_per_commitment_point_hex)
                        .map_err(|e| {
                            VlsAdapterError::Protocol(format!(
                                "invalid remote_per_commitment_point_hex: {e}"
                            ))
                        })?;
                    let remote_per_commitment_point: [u8; 33] =
                        remote_per_commitment_point.try_into().map_err(|_| {
                            VlsAdapterError::Protocol(
                                "remote_per_commitment_point must be 33 bytes".to_string(),
                            )
                        })?;
                    let htlcs = Array(
                        htlcs
                            .into_iter()
                            .map(|h| {
                                let payment_hash =
                                    hex::decode(&h.payment_hash_hex).map_err(|e| {
                                        VlsAdapterError::Protocol(format!(
                                            "invalid payment_hash_hex: {e}"
                                        ))
                                    })?;
                                let payment_hash: [u8; 32] =
                                    payment_hash.try_into().map_err(|_| {
                                        VlsAdapterError::Protocol(
                                            "payment_hash must be 32 bytes".to_string(),
                                        )
                                    })?;
                                Ok(vls_protocol::model::Htlc {
                                    side: h.side,
                                    amount: h.amount_msat,
                                    payment_hash: vls_protocol::model::Sha256(payment_hash),
                                    ctlv_expiry: h.cltv_expiry,
                                })
                            })
                            .collect::<Result<Vec<_>, VlsAdapterError>>()?,
                    );
                    let reply: SignCommitmentTxWithHtlcsReply = call(
                        dbid,
                        PubKey(peer_id),
                        &*self.transport,
                        SignRemoteCommitmentTx2 {
                            remote_per_commitment_point: PubKey(remote_per_commitment_point),
                            commitment_number,
                            feerate: feerate_sat_per_kw,
                            to_local_value_sat,
                            to_remote_value_sat,
                            htlcs,
                        },
                    )
                    .map_err(|e| {
                        VlsAdapterError::Transport(format!(
                            "sign_counterparty_commitment failed: {e:?}"
                        ))
                    })?;
                    Ok(ChannelResponse::SignatureWithHtlcs {
                        signature_hex: hex::encode(reply.signature.signature.0),
                        htlc_signatures_hex: reply
                            .htlc_signatures
                            .iter()
                            .map(|s| hex::encode(s.signature.0))
                            .collect(),
                    })
                }
                ChannelOp::SignClosingTransaction { .. }
                | ChannelOp::SignJusticeRevokedOutput { .. }
                | ChannelOp::SignJusticeRevokedHtlc { .. }
                | ChannelOp::SignHolderHtlcTransaction { .. }
                | ChannelOp::SignCounterpartyHtlcTransaction { .. }
                | ChannelOp::SignDynamicP2wshInput { .. }
                | ChannelOp::SignCounterpartyPaymentInput { .. }
                | ChannelOp::SignSplicingFundingInput { .. }
                | ChannelOp::SignHolderAnchorInput { .. }
                | ChannelOp::SignChannelAnnouncementWithFundingKey { .. } => {
                    Err(VlsAdapterError::Unsupported(format!(
                        "channel signing tx ops are not mapped in this step: {op:?}"
                    )))
                }
            }
        }

        fn sign_spendable_outputs_psbt(
            &self,
            spendable_utxos: Vec<SpendableOutputUtxo>,
            psbt: String,
        ) -> Result<String, VlsAdapterError> {
            let utxos: Vec<Utxo> = spendable_utxos
                .into_iter()
                .map(spendable_utxo_to_vls_model)
                .collect::<Result<Vec<_>, VlsAdapterError>>()?;

            let psbt_bytes = match base64::engine::general_purpose::STANDARD.decode(&psbt) {
                Ok(bytes) => bytes,
                Err(_) => hex::decode(&psbt).map_err(|e| {
                    VlsAdapterError::Protocol(format!(
                        "invalid psbt encoding (expected base64 or hex): {e}"
                    ))
                })?,
            };
            let psbt_obj = Psbt::deserialize(&psbt_bytes)
                .map_err(|e| VlsAdapterError::Protocol(format!("invalid psbt encoding: {e}")))?;
            let mut psbt_obj = psbt_obj;
            Self::normalize_psbt_input_key_origins(&mut psbt_obj);
            let streamed_psbt = StreamedPSBT::new(psbt_obj).into();

            let reply: SignWithdrawalReply = node_call(
                &*self.transport,
                SignWithdrawal {
                    utxos: Array(utxos),
                    psbt: streamed_psbt,
                },
            )
            .map_err(|e| VlsAdapterError::Transport(format!("sign_withdrawal failed: {e:?}")))?;

            Ok(base64::engine::general_purpose::STANDARD.encode(reply.psbt.0.inner.serialize()))
        }

        fn sign_rgb_psbt(
            &self,
            descriptors: Vec<String>,
            psbt: String,
        ) -> Result<String, VlsAdapterError> {
            if let Some(seed) = self.seed {
                let psbt_bytes = match base64::engine::general_purpose::STANDARD.decode(&psbt) {
                    Ok(bytes) => bytes,
                    Err(_) => hex::decode(&psbt).map_err(|e| {
                        VlsAdapterError::Protocol(format!(
                            "invalid psbt encoding (expected base64 or hex): {e}"
                        ))
                    })?,
                };
                let mut psbt_obj = Psbt::deserialize(&psbt_bytes).map_err(|e| {
                    VlsAdapterError::Protocol(format!("invalid psbt encoding: {e}"))
                })?;
                // LDK rejects funding transactions whose absolute locktime is non-final relative
                // to its best-known height. Normalize generic RGB wallet PSBTs to final form
                // before signing so channel funding transactions are always acceptable.
                psbt_obj.unsigned_tx.lock_time = bitcoin::absolute::LockTime::ZERO;
                for txin in &mut psbt_obj.unsigned_tx.input {
                    txin.sequence = bitcoin::Sequence::MAX;
                }
                let network = Network::from_str(self.network()).map_err(|e| {
                    VlsAdapterError::Protocol(format!("invalid network in adapter: {e}"))
                })?;
                let secp = Secp256k1::new();
                let master = Self::rgb_master_xpriv(&seed, network)?;
                match psbt_obj.sign(&master, &secp) {
                    Ok(_) => {
                        for input in &mut psbt_obj.inputs {
                            if input.final_script_witness.is_some() {
                                continue;
                            }
                            if let Some(sig) = input.tap_key_sig {
                                let mut witness = bitcoin::Witness::new();
                                witness.push(sig.to_vec());
                                input.final_script_witness = Some(witness);
                                input.partial_sigs.clear();
                                input.sighash_type = None;
                                input.redeem_script = None;
                                input.witness_script = None;
                                input.bip32_derivation.clear();
                                input.tap_script_sigs.clear();
                                input.tap_key_origins.clear();
                                input.tap_internal_key = None;
                                input.tap_merkle_root = None;
                            }
                        }
                        return Ok(
                            base64::engine::general_purpose::STANDARD.encode(psbt_obj.serialize())
                        );
                    }
                    Err((_used, errors)) => {
                        return Err(VlsAdapterError::Protocol(format!(
                            "native rgb psbt signing failed: {errors:?}"
                        )));
                    }
                }
            }

            let descriptors_were_empty = descriptors.is_empty();
            let psbt_bytes = match base64::engine::general_purpose::STANDARD.decode(&psbt) {
                Ok(bytes) => bytes,
                Err(_) => hex::decode(&psbt).map_err(|e| {
                    VlsAdapterError::Protocol(format!(
                        "invalid psbt encoding (expected base64 or hex): {e}"
                    ))
                })?,
            };
            let mut psbt_obj = Psbt::deserialize(&psbt_bytes)
                .map_err(|e| VlsAdapterError::Protocol(format!("invalid psbt encoding: {e}")))?;
            Self::normalize_psbt_input_key_origins(&mut psbt_obj);
            self.rewrite_output_key_origins_for_vls(&mut psbt_obj)?;

            let utxos = if descriptors_were_empty {
                self.utxos_from_psbt(&psbt_obj)?
            } else {
                let mut parsed = descriptors
                    .into_iter()
                    .map(|desc| {
                        let parsed: WithdrawalUtxo = serde_json::from_str(&desc).map_err(|e| {
                            VlsAdapterError::Protocol(format!("invalid descriptor json: {e}"))
                        })?;
                        let txid = Txid::from_str(&parsed.txid).map_err(|e| {
                            VlsAdapterError::Protocol(format!("invalid descriptor txid: {e}"))
                        })?;
                        let script = if parsed.script_hex.is_empty() {
                            Octets::EMPTY
                        } else {
                            Octets(hex::decode(parsed.script_hex).map_err(|e| {
                                VlsAdapterError::Protocol(format!(
                                    "invalid descriptor script_hex: {e}"
                                ))
                            })?)
                        };
                        Ok(Utxo {
                            txid,
                            outnum: parsed.outnum,
                            amount: parsed.amount,
                            keyindex: parsed.keyindex,
                            is_p2sh: parsed.is_p2sh,
                            script,
                            close_info: None,
                            is_in_coinbase: parsed.is_in_coinbase,
                        })
                    })
                    .collect::<Result<Vec<_>, VlsAdapterError>>()?;
                // Prefer keyindex from PSBT origins when available, even if descriptors
                // were provided upstream with stale/mismatched index metadata.
                for (idx, utxo) in parsed.iter_mut().enumerate() {
                    let keyindex_from_bip32 = psbt_obj
                        .inputs
                        .get(idx)
                        .and_then(|i| {
                            i.bip32_derivation
                                .values()
                                .next()
                                .and_then(|(_, path)| path.as_ref().last().copied())
                        })
                        .and_then(|cn| match cn {
                            ChildNumber::Normal { index } => Some(index),
                            ChildNumber::Hardened { .. } => None,
                        });
                    let keyindex_from_tap = psbt_obj
                        .inputs
                        .get(idx)
                        .and_then(|i| {
                            i.tap_key_origins
                                .values()
                                .next()
                                .and_then(|(_, (_, path))| path.as_ref().last().copied())
                        })
                        .and_then(|cn| match cn {
                            ChildNumber::Normal { index } => Some(index),
                            ChildNumber::Hardened { .. } => None,
                        });
                    if let Some(k) = keyindex_from_bip32.or(keyindex_from_tap) {
                        utxo.keyindex = k;
                    }
                }
                parsed
            };

            let utxos_for_retry = utxos
                .iter()
                .map(|u| Utxo {
                    txid: u.txid,
                    outnum: u.outnum,
                    amount: u.amount,
                    keyindex: u.keyindex,
                    is_p2sh: u.is_p2sh,
                    script: u.script.clone(),
                    close_info: None,
                    is_in_coinbase: u.is_in_coinbase,
                })
                .collect::<Vec<_>>();
            match self.sign_withdrawal_with_utxos(utxos, psbt_obj.clone()) {
                Ok(signed) => Ok(signed),
                Err(first_err) => {
                    // Compatibility retry: rgb-lib xpub watch-only mode derives inputs on /0/i,
                    // while current VLS ownership checks validate wallet inputs on /i.
                    // Keep txid/vout/amount/keyindex unchanged and normalize only the script
                    // field used by VLS ownership policy checks.
                    let mut normalized = utxos_for_retry;
                    for u in &mut normalized {
                        u.script = self.derive_one_level_taproot_script_for_keyindex(u.keyindex)?;
                    }
                    if let Ok(signed) =
                        self.sign_withdrawal_with_utxos(normalized, psbt_obj.clone())
                    {
                        return Ok(signed);
                    }
                    Err(first_err)
                }
            }
        }

        fn get_wallet_input_metadata(
            &self,
            _txid_hex: String,
            _vout: u32,
            script_pubkey_hex: Option<String>,
            amount_sat: Option<u64>,
        ) -> Result<Option<WalletInputMetadata>, VlsAdapterError> {
            let Some(script_hex) = script_pubkey_hex else {
                return Ok(None);
            };
            let script_bytes = hex::decode(&script_hex).map_err(|e| {
                VlsAdapterError::Protocol(format!("invalid script_pubkey_hex: {e}"))
            })?;
            let script = ScriptBuf::from_bytes(script_bytes);
            let Some(keyindex) = self.infer_keyindex_from_script(&script)? else {
                return Ok(None);
            };
            Ok(Some(WalletInputMetadata {
                keyindex,
                amount_sat: amount_sat.unwrap_or_default(),
                script_pubkey_hex: script_hex,
                is_p2sh: false,
            }))
        }

        fn debug_derive_addresses(
            &self,
            script_pubkey_hex: String,
            max_index: u32,
        ) -> Result<Vec<DebugDerivedAddress>, VlsAdapterError> {
            let script_bytes = hex::decode(&script_pubkey_hex).map_err(|e| {
                VlsAdapterError::Protocol(format!("invalid script_pubkey_hex: {e}"))
            })?;
            let script = ScriptBuf::from_bytes(script_bytes);
            self.derive_matches_for_script(&script, max_index)
        }
    }
}

pub struct VlsSignerAdapter<C: VlsClient> {
    client: C,
}

impl<C: VlsClient> VlsSignerAdapter<C> {
    pub fn new(client: C) -> Self {
        Self { client }
    }
}

impl<C: VlsClient> ExternalSignerBackend for VlsSignerAdapter<C> {
    fn call(&self, req: SignerRequest) -> Result<SignerResponse, SignerError> {
        match req {
            SignerRequest::Bootstrap => self
                .client
                .bootstrap()
                .map(SignerResponse::Bootstrap)
                .map_err(Into::into),

            SignerRequest::Node(node_req) => match node_req {
                NodeRequest::GetNodeId { recipient } => self
                    .client
                    .node_get_node_id(recipient)
                    .map(|node_id_hex| SignerResponse::Node(NodeResponse::NodeId { node_id_hex }))
                    .map_err(Into::into),
                NodeRequest::GetDestinationScript {
                    channel_keys_id_hex,
                } => self
                    .client
                    .node_get_destination_script(channel_keys_id_hex)
                    .map(|script_hex| SignerResponse::Node(NodeResponse::Script { script_hex }))
                    .map_err(Into::into),
                NodeRequest::GetShutdownScriptpubkey => self
                    .client
                    .node_get_shutdown_scriptpubkey()
                    .map(|script_hex| SignerResponse::Node(NodeResponse::Script { script_hex }))
                    .map_err(Into::into),
                NodeRequest::GetSecureRandomBytes => self
                    .client
                    .node_get_secure_random_bytes()
                    .map(|bytes_hex| SignerResponse::Node(NodeResponse::RandomBytes { bytes_hex }))
                    .map_err(Into::into),
                NodeRequest::Ecdh {
                    recipient,
                    other_key,
                    tweak,
                } => self
                    .client
                    .node_ecdh(recipient, other_key, tweak)
                    .map(|shared_secret_hex| {
                        SignerResponse::Node(NodeResponse::Ecdh { shared_secret_hex })
                    })
                    .map_err(Into::into),

                NodeRequest::SignInvoice { hrp, u5bytes_hex } => self
                    .client
                    .node_sign_invoice(hrp, u5bytes_hex)
                    .map(|(signature_hex, recovery_id)| {
                        SignerResponse::Node(NodeResponse::RecoverableSignature {
                            signature_hex,
                            recovery_id,
                        })
                    })
                    .map_err(Into::into),

                NodeRequest::SignBolt12Invoice { invoice } => self
                    .client
                    .node_sign_bolt12_invoice(invoice)
                    .map(|signature_hex| {
                        SignerResponse::Node(NodeResponse::Signature { signature_hex })
                    })
                    .map_err(Into::into),

                NodeRequest::SignGossipMessage { message_hex } => self
                    .client
                    .node_sign_gossip_message(message_hex)
                    .map(|signature_hex| {
                        SignerResponse::Node(NodeResponse::Signature { signature_hex })
                    })
                    .map_err(Into::into),

                NodeRequest::SignMessage { message } => self
                    .client
                    .node_sign_message(message)
                    .map(|signature_hex| {
                        SignerResponse::Node(NodeResponse::Signature { signature_hex })
                    })
                    .map_err(Into::into),
            },

            SignerRequest::Channel(channel_req) => match channel_req {
                ChannelRequest::GenerateChannelKeysId {
                    inbound,
                    channel_value_satoshis,
                    user_channel_id,
                } => self
                    .client
                    .channel_generate_keys_id(inbound, channel_value_satoshis, user_channel_id)
                    .map(|channel_keys_id_hex| {
                        SignerResponse::Channel(ChannelResponse::GeneratedChannelKeysId {
                            channel_keys_id_hex,
                        })
                    })
                    .map_err(Into::into),

                ChannelRequest::DeriveChannelSigner {
                    channel_value_satoshis,
                    channel_keys_id_hex,
                } => self
                    .client
                    .channel_derive_signer(channel_value_satoshis, channel_keys_id_hex)
                    .map(|(channel_signer_state_hex, channel_pubkeys)| {
                        SignerResponse::Channel(ChannelResponse::ChannelSignerData {
                            channel_signer_state_hex,
                            channel_pubkeys,
                        })
                    })
                    .map_err(Into::into),

                ChannelRequest::ReadChannelSigner {
                    channel_signer_state_hex,
                } => self
                    .client
                    .channel_read_signer(channel_signer_state_hex)
                    .map(|(channel_signer_state_hex, channel_pubkeys)| {
                        SignerResponse::Channel(ChannelResponse::ChannelSignerData {
                            channel_signer_state_hex,
                            channel_pubkeys,
                        })
                    })
                    .map_err(Into::into),

                ChannelRequest::Op {
                    channel_keys_id_hex,
                    op,
                } => self
                    .client
                    .channel_op(channel_keys_id_hex, op)
                    .map(SignerResponse::Channel)
                    .map_err(Into::into),
            },

            SignerRequest::SignSpendableOutputsPsbt { utxos, psbt } => self
                .client
                .sign_spendable_outputs_psbt(utxos, psbt)
                .map(|psbt| SignerResponse::SignedPsbt { psbt })
                .map_err(Into::into),

            SignerRequest::SignRgbPsbt { descriptors, psbt } => self
                .client
                .sign_rgb_psbt(descriptors, psbt)
                .map(|psbt| SignerResponse::SignedPsbt { psbt })
                .map_err(Into::into),
            SignerRequest::GetWalletInputMetadata {
                txid_hex,
                vout,
                script_pubkey_hex,
                amount_sat,
            } => self
                .client
                .get_wallet_input_metadata(txid_hex, vout, script_pubkey_hex, amount_sat)
                .map(|metadata| SignerResponse::WalletInputMetadata { metadata })
                .map_err(Into::into),
            SignerRequest::DebugDeriveAddresses {
                script_pubkey_hex,
                max_index,
            } => self
                .client
                .debug_derive_addresses(script_pubkey_hex, max_index)
                .map(|matches| SignerResponse::DebugDeriveAddresses { matches })
                .map_err(Into::into),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract::SignerIdentity;

    struct FakeClient;

    impl VlsClient for FakeClient {
        fn bootstrap(&self) -> Result<BootstrapData, VlsAdapterError> {
            let seed = [9u8; 32];
            let (a, b, c) =
                crate::ldk_keys_manager_material::derive_ldk_keys_manager_auxiliary_secret_bytes(
                    &seed,
                )
                .map_err(|e| VlsAdapterError::Protocol(format!("derive test aux keys: {e}")))?;
            Ok(BootstrapData {
                identity: SignerIdentity {
                    node_id: "n1".to_string(),
                    account_xpub_vanilla: "xv".to_string(),
                    account_xpub_colored: "xc".to_string(),
                    master_fingerprint: "ffff0000".to_string(),
                },
                protocol_version: "vls-test".to_string(),
                api_level: 1,
                ldk_inbound_payment_key_hex: hex::encode(a),
                ldk_peer_storage_key_hex: hex::encode(b),
                ldk_receive_auth_key_hex: hex::encode(c),
                async_payments_root_seed_hex: hex::encode(seed),
            })
        }

        fn node_get_node_id(&self, recipient: String) -> Result<String, VlsAdapterError> {
            if recipient != "node" {
                return Err(VlsAdapterError::Unsupported(format!(
                    "unsupported recipient for get_node_id: {recipient}"
                )));
            }
            Ok("nodeid".to_string())
        }

        fn node_get_destination_script(
            &self,
            _channel_keys_id_hex: String,
        ) -> Result<String, VlsAdapterError> {
            Err(VlsAdapterError::Unsupported(
                "destination script not supported in FakeClient".to_string(),
            ))
        }

        fn node_get_shutdown_scriptpubkey(&self) -> Result<String, VlsAdapterError> {
            Err(VlsAdapterError::Unsupported(
                "shutdown script not supported in FakeClient".to_string(),
            ))
        }

        fn node_get_secure_random_bytes(&self) -> Result<String, VlsAdapterError> {
            Ok("00".repeat(32))
        }

        fn node_ecdh(
            &self,
            _recipient: String,
            _other_key: String,
            _tweak: Option<String>,
        ) -> Result<String, VlsAdapterError> {
            Ok("ecdh-secret".to_string())
        }

        fn node_sign_invoice(
            &self,
            hrp: String,
            _u5bytes_hex: String,
        ) -> Result<(String, u8), VlsAdapterError> {
            Ok((format!("inv-sig:{hrp}"), 1))
        }

        fn node_sign_bolt12_invoice(&self, invoice: String) -> Result<String, VlsAdapterError> {
            Ok(format!("b12:{invoice}"))
        }

        fn node_sign_gossip_message(&self, message_hex: String) -> Result<String, VlsAdapterError> {
            Ok(format!("gossip:{message_hex}"))
        }

        fn node_sign_message(&self, message: String) -> Result<String, VlsAdapterError> {
            Ok(format!("msg:{message}"))
        }

        fn channel_generate_keys_id(
            &self,
            inbound: bool,
            channel_value_satoshis: u64,
            user_channel_id: u128,
        ) -> Result<String, VlsAdapterError> {
            Ok(format!(
                "kid:{inbound}:{channel_value_satoshis}:{user_channel_id}"
            ))
        }

        fn channel_derive_signer(
            &self,
            channel_value_satoshis: u64,
            channel_keys_id_hex: String,
        ) -> Result<(String, ChannelPublicKeys), VlsAdapterError> {
            Ok((
                format!("state:{channel_keys_id_hex}:{channel_value_satoshis}"),
                ChannelPublicKeys {
                    funding_pubkey_hex: "02aa".to_string(),
                    revocation_basepoint_hex: "03aa".to_string(),
                    payment_point_hex: "02bb".to_string(),
                    delayed_payment_basepoint_hex: "03bb".to_string(),
                    htlc_basepoint_hex: "02cc".to_string(),
                },
            ))
        }

        fn channel_read_signer(
            &self,
            channel_signer_state_hex: String,
        ) -> Result<(String, ChannelPublicKeys), VlsAdapterError> {
            self.channel_derive_signer(0, channel_signer_state_hex)
        }

        fn channel_op(
            &self,
            channel_keys_id_hex: String,
            _op: ChannelOp,
        ) -> Result<ChannelResponse, VlsAdapterError> {
            Ok(ChannelResponse::Signature {
                signature_hex: format!("chan-op:{channel_keys_id_hex}"),
            })
        }

        fn sign_spendable_outputs_psbt(
            &self,
            utxos: Vec<SpendableOutputUtxo>,
            psbt: String,
        ) -> Result<String, VlsAdapterError> {
            Ok(format!("signed:{}:{psbt}", utxos.len()))
        }

        fn sign_rgb_psbt(
            &self,
            descriptors: Vec<String>,
            psbt: String,
        ) -> Result<String, VlsAdapterError> {
            Ok(format!("rgb:{}:{psbt}", descriptors.len()))
        }

        fn get_wallet_input_metadata(
            &self,
            _txid_hex: String,
            _vout: u32,
            _script_pubkey_hex: Option<String>,
            _amount_sat: Option<u64>,
        ) -> Result<Option<WalletInputMetadata>, VlsAdapterError> {
            Ok(None)
        }

        fn debug_derive_addresses(
            &self,
            _script_pubkey_hex: String,
            _max_index: u32,
        ) -> Result<Vec<DebugDerivedAddress>, VlsAdapterError> {
            Ok(Vec::new())
        }
    }

    #[test]
    fn maps_bootstrap() {
        let adapter = VlsSignerAdapter::new(FakeClient);
        let res = adapter.call(SignerRequest::Bootstrap).expect("bootstrap");
        match res {
            SignerResponse::Bootstrap(data) => assert_eq!(data.identity.node_id, "n1"),
            _ => panic!("unexpected response"),
        }
    }

    #[test]
    fn maps_node_sign_message() {
        let adapter = VlsSignerAdapter::new(FakeClient);
        let res = adapter
            .call(SignerRequest::Node(NodeRequest::SignMessage {
                message: "hello".to_string(),
            }))
            .expect("sign");
        match res {
            SignerResponse::Node(NodeResponse::Signature { signature_hex }) => {
                assert_eq!(signature_hex, "msg:hello")
            }
            _ => panic!("unexpected response"),
        }
    }

    #[test]
    fn maps_channel_generate_key_id() {
        let adapter = VlsSignerAdapter::new(FakeClient);
        let res = adapter
            .call(SignerRequest::Channel(
                ChannelRequest::GenerateChannelKeysId {
                    inbound: true,
                    channel_value_satoshis: 1000,
                    user_channel_id: 7,
                },
            ))
            .expect("kid");
        match res {
            SignerResponse::Channel(ChannelResponse::GeneratedChannelKeysId {
                channel_keys_id_hex,
            }) => {
                assert_eq!(channel_keys_id_hex, "kid:true:1000:7")
            }
            _ => panic!("unexpected response"),
        }
    }

    #[test]
    fn xpub_child_derivation_changes_serialized_xpub() {
        use bitcoin::bip32::{ChildNumber, Xpub};
        use bitcoin::secp256k1::Secp256k1;
        use std::str::FromStr;

        let parent = Xpub::from_str("tpubDBtucATK3NNuZmNkDfgoKHpo4AtrxYFgZKgmtfQvbrAAGwEZpEUpJWtGgnatCYAa6v9KyeRoAoiQq4Myym74a6ufYSMQPo1a5h53H78J9kN")
            .expect("valid xpub");
        let secp = Secp256k1::verification_only();
        let child = parent
            .derive_pub(
                &secp,
                &[ChildNumber::from_normal_idx(1).expect("child index")],
            )
            .expect("derive child");
        assert_ne!(parent.to_string(), child.to_string());
    }
}
