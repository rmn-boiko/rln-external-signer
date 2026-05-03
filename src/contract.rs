use serde::{Deserialize, Serialize};

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
    pub api_level: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WalletInputMetadata {
    pub keyindex: u32,
    pub amount_sat: u64,
    pub script_pubkey_hex: String,
    pub is_p2sh: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DebugDerivedAddress {
    pub keyindex: u32,
    pub address: String,
    pub derivation: String,
    pub account: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SignerRequest {
    Bootstrap,
    Node(NodeRequest),
    Channel(ChannelRequest),
    SignSpendableOutputsPsbt {
        descriptors: Vec<String>,
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
    DebugDeriveAddresses {
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
    ValidateHolderCommitment {
        commitment_number: u64,
        feerate_sat_per_kw: u32,
        to_local_value_sat: u64,
        to_remote_value_sat: u64,
        htlcs: Vec<ChannelHtlc>,
        counterparty_signature_hex: String,
        counterparty_htlc_signatures_hex: Vec<String>,
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
    DebugDeriveAddresses {
        matches: Vec<DebugDerivedAddress>,
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
