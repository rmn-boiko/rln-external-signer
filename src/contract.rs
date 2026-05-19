use serde::{Deserialize, Serialize};

fn default_bootstrap_api_level() -> u32 {
    1
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignerIdentity {
    pub node_id: String,
    pub account_xpub_vanilla: String,
    pub account_xpub_colored: String,
    pub master_fingerprint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BootstrapData {
    pub identity: SignerIdentity,
    pub protocol_version: String,
    /// External signer wire/bootstrap compatibility. RLN currently requires **`1`** (matches
    /// `rgb_lightning_node::signer::SUPPORTED_SIGNER_API_LEVEL`). Hosts must send this value in
    /// bootstrap until a future level is defined.
    #[serde(default = "default_bootstrap_api_level")]
    pub api_level: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AsyncPaymentsHashEntry {
    pub hash_index: u64,
    pub payment_hash_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WalletInputMetadata {
    pub keyindex: u32,
    pub amount_sat: u64,
    pub script_pubkey_hex: String,
    pub is_p2sh: bool,
}

/// UTXO metadata for [`SignerRequest::SignSpendableOutputsPsbt`] (LDK spendable outputs → VLS withdrawal).
/// Carried as protobuf sub-messages on the signer wire, not JSON.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SpendableOutputUtxo {
    pub txid_hex: String,
    pub vout: u32,
    pub amount_sat: u64,
    pub keyindex: u32,
    #[serde(default)]
    pub is_p2sh: bool,
    #[serde(default)]
    pub script_pubkey_hex: String,
    #[serde(default)]
    pub is_in_coinbase: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SpendableDescriptorKind {
    StaticOutput,
    StaticPaymentOutput,
    DelayedPaymentOutput,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WalletDerivationMatch {
    pub account_name: String,
    pub keyindex: u32,
    pub derivation_path: String,
}

/// Richer spendable-output signing metadata for
/// [`SignerRequest::SignSpendableOutputsPsbt`].
///
/// This is the forward-looking contract used to fully externalize LDK
/// spendable-output signing. It carries descriptor classification and optional
/// wallet/channel context that is currently unavailable in the legacy
/// [`SpendableOutputUtxo`] shape.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SpendableOutputSignInput {
    pub descriptor_kind: SpendableDescriptorKind,
    pub txid_hex: String,
    pub vout: u32,
    pub amount_sat: u64,
    pub script_pubkey_hex: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel_keys_id_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wallet_derivation_match: Option<WalletDerivationMatch>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub witness_script_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redeem_script_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub per_commitment_point_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to_self_delay: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DerivedAddressMatch {
    pub keyindex: u32,
    pub address: String,
    #[serde(alias = "derivation")]
    pub derivation_path: String,
    #[serde(alias = "account")]
    pub account_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SignerRequest {
    Bootstrap,
    Node(NodeRequest),
    Channel(ChannelRequest),
    SignSpendableOutputsPsbt {
        inputs: Vec<SpendableOutputSignInput>,
        psbt: String,
    },
    SignRgbPsbt {
        descriptors: Vec<String>,
        psbt: String,
    },
    GetWalletInputMetadata {
        txid_hex: String,
        vout: u32,
        script_pubkey_hex: Option<String>,
        amount_sat: Option<u64>,
    },
    #[serde(alias = "DebugDeriveAddresses")]
    FindDerivationMatches {
        script_pubkey_hex: String,
        max_index: u32,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum NodeRequest {
    GetNodeId {
        recipient: String,
    },
    GetDestinationScript {
        channel_keys_id_hex: String,
    },
    GetShutdownScriptpubkey,
    GetSecureRandomBytes,
    EncryptPeerStoragePayload {
        plaintext_hex: String,
        random_bytes_hex: String,
    },
    DecryptPeerStoragePayload {
        ciphertext_hex: String,
    },
    EncryptBlindedMessagePayload {
        plaintext_hex: String,
        rho_hex: String,
    },
    DecryptBlindedMessagePayload {
        ciphertext_hex: String,
        rho_hex: String,
    },
    GetHmacForOfferKey,
    CryptForOffer {
        bytes_hex: String,
        nonce_hex: String,
    },
    PrepareAsyncPaymentsHashes {
        host_node_id_hex: String,
        start_index: u64,
        batch_size: u32,
    },
    CreateInboundPayment {
        min_value_msat: Option<u64>,
        invoice_expiry_delta_secs: u32,
        random_bytes_hex: String,
        current_time: u64,
        min_final_cltv_expiry_delta: Option<u16>,
    },
    CreateInboundPaymentForHash {
        payment_hash_hex: String,
        min_value_msat: Option<u64>,
        invoice_expiry_delta_secs: u32,
        current_time: u64,
        min_final_cltv_expiry_delta: Option<u16>,
    },
    CreateSpontaneousPaymentSecret {
        min_value_msat: Option<u64>,
        invoice_expiry_delta_secs: u32,
        current_time: u64,
        min_final_cltv_expiry_delta: Option<u16>,
    },
    VerifyInboundPayment {
        payment_hash_hex: String,
        payment_secret_hex: String,
        total_msat: u64,
        highest_seen_timestamp: u64,
    },
    GetPaymentPreimage {
        payment_hash_hex: String,
        payment_secret_hex: String,
    },
    Ecdh {
        recipient: String,
        other_key: String,
        tweak: Option<String>,
    },
    SignInvoice {
        hrp: String,
        u5bytes_hex: String,
    },
    SignBolt12Invoice {
        invoice: String,
    },
    SignGossipMessage {
        message_hex: String,
    },
    SignMessage {
        message: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum NodeResponse {
    NodeId {
        node_id_hex: String,
    },
    Script {
        script_hex: String,
    },
    RandomBytes {
        bytes_hex: String,
    },
    PeerStoragePayload {
        bytes_hex: String,
    },
    DecryptedPeerStoragePayload {
        bytes_hex: String,
    },
    BlindedMessagePayload {
        bytes_hex: String,
    },
    DecryptedBlindedMessagePayload {
        bytes_hex: String,
        used_aad: bool,
    },
    HmacForOfferKey {
        key_hex: String,
    },
    CryptForOffer {
        bytes_hex: String,
    },
    AsyncPaymentsHashes {
        hashes: Vec<AsyncPaymentsHashEntry>,
    },
    PaymentHashAndSecret {
        payment_hash_hex: String,
        payment_secret_hex: String,
    },
    PaymentSecret {
        payment_secret_hex: String,
    },
    VerifyInboundPayment {
        payment_preimage_hex: Option<String>,
        min_final_cltv_expiry_delta: Option<u16>,
    },
    PaymentPreimage {
        payment_preimage_hex: String,
    },
    Ecdh {
        shared_secret_hex: String,
    },
    RecoverableSignature {
        signature_hex: String,
        recovery_id: u8,
    },
    Signature {
        signature_hex: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ChannelRequest {
    GenerateChannelKeysId {
        inbound: bool,
        channel_value_satoshis: u64,
        user_channel_id: u128,
    },
    DeriveChannelSigner {
        channel_value_satoshis: u64,
        channel_keys_id_hex: String,
    },
    ReadChannelSigner {
        channel_signer_state_hex: String,
    },
    Op {
        channel_keys_id_hex: String,
        op: ChannelOp,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChannelHtlc {
    pub side: u8,
    pub amount_msat: u64,
    pub payment_hash_hex: String,
    pub cltv_expiry: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ChannelOp {
    SetupChannel {
        is_outbound: bool,
        channel_value_satoshis: u64,
        push_value_msat: u64,
        funding_txid_hex: String,
        funding_vout: u16,
        holder_selected_contest_delay: u16,
        counterparty_pubkeys: ChannelPublicKeys,
        counterparty_selected_contest_delay: u16,
        channel_type_kind: u8,
    },
    GetPerCommitmentPoint {
        idx: u64,
    },
    ReleaseCommitmentSecret {
        idx: u64,
    },
    /// Validate counterparty signatures on the holder commitment (LDK / VLS).
    ///
    /// - `commitment_unsigned_tx_hex`: when `Some` and non-empty after trimming, **hex-encoded
    ///   consensus serialization** of the **unsigned** holder commitment transaction. The VLS
    ///   adapter uses the full-tx protocol message so the signer verifies ECDSA on those bytes
    ///   (needed when outputs include e.g. RGB `OP_RETURN`). When `None` or omitted in JSON, the
    ///   adapter uses the summary-only LDK message (`ValidateCommitmentTx2`).
    ValidateHolderCommitment {
        commitment_number: u64,
        feerate_sat_per_kw: u32,
        to_local_value_sat: u64,
        to_remote_value_sat: u64,
        htlcs: Vec<ChannelHtlc>,
        counterparty_signature_hex: String,
        counterparty_htlc_signatures_hex: Vec<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        commitment_unsigned_tx_hex: Option<String>,
        /// Hex-encoded witness redeem scripts, one per transaction output (aligned with
        /// `commitment_unsigned_tx_hex` outputs). When set with the wire tx, the VLS adapter fills
        /// PSBT `witness_script` fields required for P2WSH decode.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        commitment_psbt_output_witness_scripts_hex: Option<Vec<String>>,
    },
    SignHolderCommitment {
        tx_hex: String,
        commitment_number: u64,
    },
    SignCounterpartyCommitment {
        tx_hex: String,
        remote_per_commitment_point_hex: String,
        commitment_number: u64,
        feerate_sat_per_kw: u32,
        to_local_value_sat: u64,
        to_remote_value_sat: u64,
        htlcs: Vec<ChannelHtlc>,
        preimages_hex: Vec<String>,
        /// Hex-encoded witness redeem scripts, one per transaction output (aligned with `tx_hex`
        /// outputs). Needed when signing RGB-shaped counterparty commitments over the full wire tx.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        commitment_psbt_output_witness_scripts_hex: Option<Vec<String>>,
    },
    SignClosingTransaction {
        tx_hex: String,
    },
    SignJusticeRevokedOutput {
        tx_hex: String,
        input: u32,
        amount_sat: u64,
        per_commitment_key_hex: String,
    },
    SignJusticeRevokedHtlc {
        tx_hex: String,
        input: u32,
        amount_sat: u64,
        per_commitment_key_hex: String,
        htlc_hex: String,
    },
    SignHolderHtlcTransaction {
        tx_hex: String,
        input: u32,
        htlc_descriptor_hex: String,
    },
    SignCounterpartyHtlcTransaction {
        tx_hex: String,
        input: u32,
        amount_sat: u64,
        per_commitment_point_hex: String,
        htlc_descriptor_hex: String,
    },
    SignDynamicP2wshInput {
        tx_hex: String,
        input: u32,
        descriptor_hex: String,
    },
    SignCounterpartyPaymentInput {
        tx_hex: String,
        input: u32,
        descriptor_hex: String,
    },
    SignSplicingFundingInput {
        tx_hex: String,
        input: u32,
        txin_descriptor_hex: String,
    },
    SignHolderAnchorInput {
        tx_hex: String,
        input: u32,
        descriptor_hex: String,
    },
    SignChannelAnnouncementWithFundingKey {
        msg_hex: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ChannelResponse {
    GeneratedChannelKeysId {
        channel_keys_id_hex: String,
    },
    SetupComplete,
    ValidationComplete,
    ChannelSignerData {
        channel_signer_state_hex: String,
        channel_pubkeys: ChannelPublicKeys,
    },
    PerCommitmentPoint {
        point_hex: String,
    },
    CommitmentSecret {
        secret_hex: String,
    },
    Signature {
        signature_hex: String,
    },
    SignatureWithHtlcs {
        signature_hex: String,
        htlc_signatures_hex: Vec<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChannelPublicKeys {
    pub funding_pubkey_hex: String,
    pub revocation_basepoint_hex: String,
    pub payment_point_hex: String,
    pub delayed_payment_basepoint_hex: String,
    pub htlc_basepoint_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SignerResponse {
    Bootstrap(BootstrapData),
    Node(NodeResponse),
    Channel(ChannelResponse),
    SignedPsbt {
        psbt: String,
    },
    WalletInputMetadata {
        metadata: Option<WalletInputMetadata>,
    },
    #[serde(alias = "DebugDeriveAddresses")]
    FindDerivationMatches {
        matches: Vec<DerivedAddressMatch>,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum SignerError {
    #[error("transport error: {0}")]
    Transport(String),
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("unsupported operation: {0}")]
    Unsupported(String),
}

pub trait ExternalSignerBackend: Send + Sync {
    fn call(&self, req: SignerRequest) -> Result<SignerResponse, SignerError>;
}

#[cfg(test)]
mod validate_holder_commitment_contract_tests {
    use super::{ChannelHtlc, ChannelOp};

    #[test]
    fn validate_holder_commitment_serde_roundtrip_with_and_without_wire_tx_hex() {
        let op_none = ChannelOp::ValidateHolderCommitment {
            commitment_number: 7,
            feerate_sat_per_kw: 253,
            to_local_value_sat: 10_000,
            to_remote_value_sat: 20_000,
            htlcs: vec![],
            counterparty_signature_hex: "ab".repeat(64),
            counterparty_htlc_signatures_hex: vec![],
            commitment_unsigned_tx_hex: None,
            commitment_psbt_output_witness_scripts_hex: None,
        };
        let j = serde_json::to_string(&op_none).unwrap();
        let back: ChannelOp = serde_json::from_str(&j).unwrap();
        assert_eq!(back, op_none);

        let op_some = ChannelOp::ValidateHolderCommitment {
            commitment_number: 8,
            feerate_sat_per_kw: 1000,
            to_local_value_sat: 1,
            to_remote_value_sat: 2,
            htlcs: vec![ChannelHtlc {
                side: 0,
                amount_msat: 3000,
                payment_hash_hex: "cc".repeat(32),
                cltv_expiry: 100,
            }],
            counterparty_signature_hex: "dd".repeat(64),
            counterparty_htlc_signatures_hex: vec!["ee".repeat(64)],
            commitment_unsigned_tx_hex: Some("01000000000100".to_string()),
            commitment_psbt_output_witness_scripts_hex: None,
        };
        let j = serde_json::to_string(&op_some).unwrap();
        let back: ChannelOp = serde_json::from_str(&j).unwrap();
        assert_eq!(back, op_some);
    }
}
