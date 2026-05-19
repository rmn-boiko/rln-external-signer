use crate::contract::{
    AsyncPaymentsHashEntry, BootstrapData, ChannelOp, ChannelPublicKeys, ChannelRequest,
    ChannelResponse, DerivedAddressMatch, ExternalSignerBackend, NodeRequest, NodeResponse,
    SignerError, SignerRequest, SignerResponse, SpendableOutputSignInput, WalletInputMetadata,
};
use bitcoin::hashes::cmp::fixed_time_eq;
use bitcoin::hashes::hmac::HmacEngine;
use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::{Hash, HashEngine};
use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, KeyInit, Nonce, Tag};
use poly1305::universal_hash::UniversalHash;
use poly1305::Poly1305;

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

fn hkdf_extract_expand_6x_local(
    salt: &[u8],
    ikm: &[u8],
) -> ([u8; 32], [u8; 32], [u8; 32], [u8; 32], [u8; 32], [u8; 32]) {
    let mut hmac = HmacEngine::<Sha256>::new(salt);
    hmac.input(ikm);
    let prk = bitcoin::hashes::hmac::Hmac::<Sha256>::from_engine(hmac).to_byte_array();

    let mut hmac = HmacEngine::<Sha256>::new(&prk[..]);
    hmac.input(&[1; 1]);
    let k1 = bitcoin::hashes::hmac::Hmac::<Sha256>::from_engine(hmac).to_byte_array();

    let mut hmac = HmacEngine::<Sha256>::new(&prk[..]);
    hmac.input(&k1);
    hmac.input(&[2; 1]);
    let k2 = bitcoin::hashes::hmac::Hmac::<Sha256>::from_engine(hmac).to_byte_array();

    let mut hmac = HmacEngine::<Sha256>::new(&prk[..]);
    hmac.input(&k2);
    hmac.input(&[3; 1]);
    let k3 = bitcoin::hashes::hmac::Hmac::<Sha256>::from_engine(hmac).to_byte_array();

    let mut hmac = HmacEngine::<Sha256>::new(&prk[..]);
    hmac.input(&k3);
    hmac.input(&[4; 1]);
    let k4 = bitcoin::hashes::hmac::Hmac::<Sha256>::from_engine(hmac).to_byte_array();

    let mut hmac = HmacEngine::<Sha256>::new(&prk[..]);
    hmac.input(&k4);
    hmac.input(&[5; 1]);
    let k5 = bitcoin::hashes::hmac::Hmac::<Sha256>::from_engine(hmac).to_byte_array();

    let mut hmac = HmacEngine::<Sha256>::new(&prk[..]);
    hmac.input(&k5);
    hmac.input(&[6; 1]);
    let k6 = bitcoin::hashes::hmac::Hmac::<Sha256>::from_engine(hmac).to_byte_array();

    (k1, k2, k3, k4, k5, k6)
}

pub(crate) fn offer_keys_from_inbound_key_hex(
    ldk_inbound_payment_key_hex: &str,
) -> Result<([u8; 32], [u8; 32]), VlsAdapterError> {
    let inbound_key = hex::decode(ldk_inbound_payment_key_hex)
        .map_err(|e| VlsAdapterError::Protocol(format!("invalid inbound payment key hex: {e}")))?;
    let inbound_key: [u8; 32] = inbound_key.try_into().map_err(|_| {
        VlsAdapterError::Protocol("inbound payment key must decode to 32 bytes".to_string())
    })?;
    let (_, _, _, offers_base_key, offers_encryption_key, _) =
        hkdf_extract_expand_6x_local(b"LDK Inbound Payment Key Expansion", &inbound_key);
    Ok((offers_base_key, offers_encryption_key))
}

pub(crate) fn crypt_for_offer_local(
    ldk_inbound_payment_key_hex: &str,
    bytes_hex: String,
    nonce_hex: String,
) -> Result<String, VlsAdapterError> {
    let (_offers_base_key, offers_encryption_key) =
        offer_keys_from_inbound_key_hex(ldk_inbound_payment_key_hex)?;
    let bytes = hex::decode(&bytes_hex)
        .map_err(|e| VlsAdapterError::Protocol(format!("invalid bytes_hex: {e}")))?;
    let mut bytes_arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| VlsAdapterError::Protocol("bytes_hex must decode to 32 bytes".to_string()))?;
    let nonce = hex::decode(&nonce_hex)
        .map_err(|e| VlsAdapterError::Protocol(format!("invalid nonce_hex: {e}")))?;
    let nonce: [u8; 16] = nonce
        .as_slice()
        .try_into()
        .map_err(|_| VlsAdapterError::Protocol("nonce_hex must decode to 16 bytes".to_string()))?;
    let mut nonce_12 = [0u8; 12];
    nonce_12.copy_from_slice(&nonce[4..]);
    let counter = u32::from_le_bytes(nonce[..4].try_into().expect("fixed size"));
    let mut cipher = chacha20::ChaCha20::new((&offers_encryption_key).into(), (&nonce_12).into());
    cipher.seek((counter as u64) * 64);
    cipher.apply_keystream(&mut bytes_arr);
    Ok(hex::encode(bytes_arr))
}

pub(crate) fn encrypt_blinded_message_payload_local(
    ldk_receive_auth_key_hex: &str,
    plaintext_hex: String,
    rho_hex: String,
) -> Result<String, VlsAdapterError> {
    let key = hex::decode(ldk_receive_auth_key_hex)
        .map_err(|e| VlsAdapterError::Protocol(format!("invalid receive auth key hex: {e}")))?;
    let key: [u8; 32] = key.try_into().map_err(|_| {
        VlsAdapterError::Protocol("receive auth key must decode to 32 bytes".to_string())
    })?;
    let rho = hex::decode(&rho_hex)
        .map_err(|e| VlsAdapterError::Protocol(format!("invalid rho_hex: {e}")))?;
    let rho: [u8; 32] = rho
        .try_into()
        .map_err(|_| VlsAdapterError::Protocol("rho_hex must decode to 32 bytes".to_string()))?;
    let mut plaintext = hex::decode(&plaintext_hex)
        .map_err(|e| VlsAdapterError::Protocol(format!("invalid plaintext_hex: {e}")))?;

    let mut chacha = chacha20::ChaCha20::new((&key).into(), (&[0u8; 12]).into());
    let mut mac_key = [0u8; 64];
    chacha.apply_keystream(&mut mac_key);

    let mut mac = Poly1305::new((&mac_key[..32]).into());
    chacha.apply_keystream(&mut plaintext);
    mac.update_padded(&plaintext);
    mac.update_padded(&rho);
    mac.update_padded(&(plaintext.len() as u64).to_le_bytes());
    mac.update_padded(&(32u64).to_le_bytes());
    let tag = mac.finalize();

    plaintext.extend_from_slice(tag.as_slice());
    Ok(hex::encode(plaintext))
}

pub(crate) fn decrypt_blinded_message_payload_local(
    ldk_receive_auth_key_hex: &str,
    ciphertext_hex: String,
    rho_hex: String,
) -> Result<(String, bool), VlsAdapterError> {
    let key = hex::decode(ldk_receive_auth_key_hex)
        .map_err(|e| VlsAdapterError::Protocol(format!("invalid receive auth key hex: {e}")))?;
    let key: [u8; 32] = key.try_into().map_err(|_| {
        VlsAdapterError::Protocol("receive auth key must decode to 32 bytes".to_string())
    })?;
    let rho = hex::decode(&rho_hex)
        .map_err(|e| VlsAdapterError::Protocol(format!("invalid rho_hex: {e}")))?;
    let rho: [u8; 32] = rho
        .try_into()
        .map_err(|_| VlsAdapterError::Protocol("rho_hex must decode to 32 bytes".to_string()))?;
    let ciphertext = hex::decode(&ciphertext_hex)
        .map_err(|e| VlsAdapterError::Protocol(format!("invalid ciphertext_hex: {e}")))?;
    if ciphertext.len() < 16 {
        return Err(VlsAdapterError::Protocol(
            "ciphertext too short for blinded payload".to_string(),
        ));
    }

    let mut chacha = chacha20::ChaCha20::new((&key).into(), (&[0u8; 12]).into());
    let mut mac_key = [0u8; 64];
    chacha.apply_keystream(&mut mac_key);

    let decrypted_len = ciphertext.len() - 16;
    let mut plaintext = ciphertext[..decrypted_len].to_vec();
    let mut mac = Poly1305::new((&mac_key[..32]).into());
    mac.update_padded(&plaintext);
    chacha.apply_keystream(&mut plaintext);

    let mut mac_aad = mac.clone();
    mac_aad.update_padded(&rho);
    mac_aad.update_padded(&(decrypted_len as u64).to_le_bytes());
    mac_aad.update_padded(&(32u64).to_le_bytes());

    mac.update_padded(&(0u64).to_le_bytes());
    mac.update_padded(&(decrypted_len as u64).to_le_bytes());

    let tag = &ciphertext[decrypted_len..];
    let mac_tag = mac.finalize();
    let mac_aad_tag = mac_aad.finalize();

    if fixed_time_eq(mac_tag.as_slice(), tag) {
        Ok((hex::encode(plaintext), false))
    } else if fixed_time_eq(mac_aad_tag.as_slice(), tag) {
        Ok((hex::encode(plaintext), true))
    } else {
        Err(VlsAdapterError::Protocol(
            "invalid blinded payload authentication tag".to_string(),
        ))
    }
}

fn derive_peer_storage_nonce(
    peer_storage_key_hex: &str,
    random_bytes: &[u8],
) -> Result<[u8; 12], VlsAdapterError> {
    let key = hex::decode(peer_storage_key_hex)
        .map_err(|e| VlsAdapterError::Protocol(format!("invalid peer storage key hex: {e}")))?;
    let key: [u8; 32] = key.try_into().map_err(|_| {
        VlsAdapterError::Protocol("peer storage key must decode to 32 bytes".to_string())
    })?;
    let key_hash = Sha256::hash(&key);
    let mut hmac = HmacEngine::<Sha256>::new(key_hash.as_byte_array());
    hmac.input(random_bytes);
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&bitcoin::hashes::Hmac::from_engine(hmac).to_byte_array()[0..8]);
    Ok(nonce)
}

pub(crate) fn encrypt_peer_storage_payload_local(
    peer_storage_key_hex: &str,
    plaintext_hex: String,
    random_bytes_hex: String,
) -> Result<String, VlsAdapterError> {
    let key = hex::decode(peer_storage_key_hex)
        .map_err(|e| VlsAdapterError::Protocol(format!("invalid peer storage key hex: {e}")))?;
    let key: [u8; 32] = key.try_into().map_err(|_| {
        VlsAdapterError::Protocol("peer storage key must decode to 32 bytes".to_string())
    })?;
    let random_bytes = hex::decode(&random_bytes_hex)
        .map_err(|e| VlsAdapterError::Protocol(format!("invalid random_bytes_hex: {e}")))?;
    let random_bytes: [u8; 32] = random_bytes.try_into().map_err(|_| {
        VlsAdapterError::Protocol("random_bytes_hex must decode to 32 bytes".to_string())
    })?;
    let nonce = derive_peer_storage_nonce(peer_storage_key_hex, &random_bytes)?;
    let mut plaintext = hex::decode(&plaintext_hex)
        .map_err(|e| VlsAdapterError::Protocol(format!("invalid plaintext_hex: {e}")))?;
    let cipher = ChaCha20Poly1305::new((&key).into());
    let tag = cipher
        .encrypt_in_place_detached(Nonce::from_slice(&nonce), b"", &mut plaintext)
        .map_err(|_| VlsAdapterError::Protocol("peer storage encryption failed".to_string()))?;
    plaintext.extend_from_slice(tag.as_slice());
    plaintext.extend_from_slice(&random_bytes);
    Ok(hex::encode(plaintext))
}

pub(crate) fn decrypt_peer_storage_payload_local(
    peer_storage_key_hex: &str,
    ciphertext_hex: String,
) -> Result<String, VlsAdapterError> {
    let key = hex::decode(peer_storage_key_hex)
        .map_err(|e| VlsAdapterError::Protocol(format!("invalid peer storage key hex: {e}")))?;
    let key: [u8; 32] = key.try_into().map_err(|_| {
        VlsAdapterError::Protocol("peer storage key must decode to 32 bytes".to_string())
    })?;
    let mut ciphertext = hex::decode(&ciphertext_hex)
        .map_err(|e| VlsAdapterError::Protocol(format!("invalid ciphertext_hex: {e}")))?;
    if ciphertext.len() < 48 {
        return Err(VlsAdapterError::Protocol(
            "ciphertext too short for peer storage payload".to_string(),
        ));
    }
    let total_len = ciphertext.len();
    let random_start = total_len - 32;
    let tag_start = random_start - 16;
    let random_bytes = ciphertext[random_start..].to_vec();
    let nonce = derive_peer_storage_nonce(peer_storage_key_hex, &random_bytes)?;
    let tag = Tag::clone_from_slice(&ciphertext[tag_start..random_start]);
    ciphertext.truncate(tag_start);
    let cipher = ChaCha20Poly1305::new((&key).into());
    cipher
        .decrypt_in_place_detached(Nonce::from_slice(&nonce), b"", &mut ciphertext, &tag)
        .map_err(|_| VlsAdapterError::Protocol("peer storage decryption failed".to_string()))?;
    Ok(hex::encode(ciphertext))
}

const INBOUND_IV_LEN: usize = 16;
const INBOUND_METADATA_LEN: usize = 16;
const INBOUND_METADATA_KEY_LEN: usize = 32;
const INBOUND_AMT_MSAT_LEN: usize = 8;
const INBOUND_METHOD_TYPE_OFFSET: usize = 5;
const MAX_VALUE_MSAT_LOCAL: u64 = 21_000_000u64 * 100_000_000u64 * 1000u64;

#[derive(Copy, Clone)]
struct ExpandedInboundKeys {
    metadata_key: [u8; 32],
    ldk_pmt_hash_key: [u8; 32],
    user_pmt_hash_key: [u8; 32],
    spontaneous_pmt_key: [u8; 32],
}

#[derive(Copy, Clone)]
enum InboundMethod {
    LdkPaymentHash = 0,
    UserPaymentHash = 1,
    LdkPaymentHashCustomFinalCltv = 2,
    UserPaymentHashCustomFinalCltv = 3,
    SpontaneousPayment = 4,
}

impl InboundMethod {
    fn from_bits(bits: u8) -> Result<Self, VlsAdapterError> {
        match bits {
            0 => Ok(Self::LdkPaymentHash),
            1 => Ok(Self::UserPaymentHash),
            2 => Ok(Self::LdkPaymentHashCustomFinalCltv),
            3 => Ok(Self::UserPaymentHashCustomFinalCltv),
            4 => Ok(Self::SpontaneousPayment),
            other => Err(VlsAdapterError::Protocol(format!(
                "unknown inbound payment type bits: {other}"
            ))),
        }
    }
}

fn expanded_keys_from_inbound_key_hex(
    ldk_inbound_payment_key_hex: &str,
) -> Result<ExpandedInboundKeys, VlsAdapterError> {
    let inbound_key = hex::decode(ldk_inbound_payment_key_hex)
        .map_err(|e| VlsAdapterError::Protocol(format!("invalid inbound payment key hex: {e}")))?;
    let inbound_key: [u8; 32] = inbound_key.try_into().map_err(|_| {
        VlsAdapterError::Protocol("inbound payment key must decode to 32 bytes".to_string())
    })?;
    let (
        metadata_key,
        ldk_pmt_hash_key,
        user_pmt_hash_key,
        _offers_base_key,
        _offers_encryption_key,
        spontaneous_pmt_key,
    ) = hkdf_extract_expand_6x_local(b"LDK Inbound Payment Key Expansion", &inbound_key);
    Ok(ExpandedInboundKeys {
        metadata_key,
        ldk_pmt_hash_key,
        user_pmt_hash_key,
        spontaneous_pmt_key,
    })
}

fn calculate_absolute_expiry_local(highest_seen_timestamp: u64, invoice_expiry_delta_secs: u32) -> u64 {
    highest_seen_timestamp + invoice_expiry_delta_secs as u64 + 7200
}

fn construct_metadata_bytes_local(
    min_value_msat: Option<u64>,
    payment_type: InboundMethod,
    invoice_expiry_delta_secs: u32,
    highest_seen_timestamp: u64,
    min_final_cltv_expiry_delta: Option<u16>,
) -> Result<[u8; INBOUND_METADATA_LEN], VlsAdapterError> {
    if min_value_msat.is_some_and(|amt| amt > MAX_VALUE_MSAT_LOCAL) {
        return Err(VlsAdapterError::Protocol(
            "min_value_msat exceeds MAX_VALUE_MSAT".to_string(),
        ));
    }
    if min_value_msat.is_some_and(|amt| amt > ((1u64 << 61) - 1)) {
        return Err(VlsAdapterError::Protocol(
            "min_value_msat exceeds 61-bit encoded limit".to_string(),
        ));
    }

    let mut min_amt_msat_bytes = min_value_msat.unwrap_or_default().to_be_bytes();
    min_amt_msat_bytes[0] |= (payment_type as u8) << INBOUND_METHOD_TYPE_OFFSET;

    let expiry_timestamp =
        calculate_absolute_expiry_local(highest_seen_timestamp, invoice_expiry_delta_secs);
    if min_final_cltv_expiry_delta.is_some() && expiry_timestamp > ((1u64 << 48) - 1) {
        return Err(VlsAdapterError::Protocol(
            "expiry timestamp exceeds 48-bit encoded limit".to_string(),
        ));
    }

    let mut expiry_bytes = expiry_timestamp.to_be_bytes();
    if let Some(delta) = min_final_cltv_expiry_delta {
        let delta_bytes = delta.to_be_bytes();
        expiry_bytes[0] |= delta_bytes[0];
        expiry_bytes[1] |= delta_bytes[1];
    }

    let mut metadata_bytes = [0u8; INBOUND_METADATA_LEN];
    metadata_bytes[..INBOUND_AMT_MSAT_LEN].copy_from_slice(&min_amt_msat_bytes);
    metadata_bytes[INBOUND_AMT_MSAT_LEN..].copy_from_slice(&expiry_bytes);
    Ok(metadata_bytes)
}

fn crypt_single_block_local(
    key: &[u8; 32],
    iv: &[u8; INBOUND_IV_LEN],
    bytes: &[u8; INBOUND_METADATA_LEN],
) -> [u8; INBOUND_METADATA_LEN] {
    let mut out = *bytes;
    let mut nonce_12 = [0u8; 12];
    nonce_12.copy_from_slice(&iv[4..]);
    let counter = u32::from_le_bytes(iv[..4].try_into().expect("fixed size"));
    let mut cipher = chacha20::ChaCha20::new(key.into(), (&nonce_12).into());
    cipher.seek((counter as u64) * 64);
    cipher.apply_keystream(&mut out);
    out
}

fn construct_payment_secret_local(
    iv_bytes: &[u8; INBOUND_IV_LEN],
    metadata_bytes: &[u8; INBOUND_METADATA_LEN],
    metadata_key: &[u8; INBOUND_METADATA_KEY_LEN],
) -> [u8; 32] {
    let mut payment_secret_bytes = [0u8; 32];
    payment_secret_bytes[..INBOUND_IV_LEN].copy_from_slice(iv_bytes);
    let encrypted = crypt_single_block_local(metadata_key, iv_bytes, metadata_bytes);
    payment_secret_bytes[INBOUND_IV_LEN..].copy_from_slice(&encrypted);
    payment_secret_bytes
}

fn decrypt_metadata_local(
    payment_secret: [u8; 32],
    keys: &ExpandedInboundKeys,
) -> ([u8; INBOUND_IV_LEN], [u8; INBOUND_METADATA_LEN]) {
    let mut iv_bytes = [0u8; INBOUND_IV_LEN];
    iv_bytes.copy_from_slice(&payment_secret[..INBOUND_IV_LEN]);
    let mut encrypted_metadata = [0u8; INBOUND_METADATA_LEN];
    encrypted_metadata.copy_from_slice(&payment_secret[INBOUND_IV_LEN..]);
    let metadata_bytes =
        crypt_single_block_local(&keys.metadata_key, &iv_bytes, &encrypted_metadata);
    (iv_bytes, metadata_bytes)
}

fn derive_ldk_payment_preimage_local(
    payment_hash: [u8; 32],
    iv_bytes: &[u8; INBOUND_IV_LEN],
    metadata_bytes: &[u8; INBOUND_METADATA_LEN],
    keys: &ExpandedInboundKeys,
) -> Result<[u8; 32], [u8; 32]> {
    let mut hmac = HmacEngine::<Sha256>::new(&keys.ldk_pmt_hash_key);
    hmac.input(iv_bytes);
    hmac.input(metadata_bytes);
    let decoded_payment_preimage = bitcoin::hashes::hmac::Hmac::<Sha256>::from_engine(hmac).to_byte_array();
    if !fixed_time_eq(&payment_hash, &Sha256::hash(&decoded_payment_preimage).to_byte_array()) {
        return Err(decoded_payment_preimage);
    }
    Ok(decoded_payment_preimage)
}

fn min_final_cltv_expiry_delta_from_metadata_local(
    bytes: [u8; INBOUND_METADATA_LEN],
) -> u16 {
    let expiry_bytes = &bytes[INBOUND_AMT_MSAT_LEN..];
    u16::from_be_bytes([expiry_bytes[0], expiry_bytes[1]])
}

fn create_inbound_payment_local(
    keys: &ExpandedInboundKeys,
    min_value_msat: Option<u64>,
    invoice_expiry_delta_secs: u32,
    random_bytes: [u8; 32],
    current_time: u64,
    min_final_cltv_expiry_delta: Option<u16>,
) -> Result<([u8; 32], [u8; 32]), VlsAdapterError> {
    let metadata_bytes = construct_metadata_bytes_local(
        min_value_msat,
        if min_final_cltv_expiry_delta.is_some() {
            InboundMethod::LdkPaymentHashCustomFinalCltv
        } else {
            InboundMethod::LdkPaymentHash
        },
        invoice_expiry_delta_secs,
        current_time,
        min_final_cltv_expiry_delta,
    )?;
    let mut iv_bytes = [0u8; INBOUND_IV_LEN];
    iv_bytes.copy_from_slice(&random_bytes[..INBOUND_IV_LEN]);
    let mut hmac = HmacEngine::<Sha256>::new(&keys.ldk_pmt_hash_key);
    hmac.input(&iv_bytes);
    hmac.input(&metadata_bytes);
    let payment_preimage = bitcoin::hashes::hmac::Hmac::<Sha256>::from_engine(hmac).to_byte_array();
    let payment_hash = Sha256::hash(&payment_preimage).to_byte_array();
    let payment_secret =
        construct_payment_secret_local(&iv_bytes, &metadata_bytes, &keys.metadata_key);
    Ok((payment_hash, payment_secret))
}

fn create_inbound_payment_for_hash_local(
    keys: &ExpandedInboundKeys,
    min_value_msat: Option<u64>,
    payment_hash: [u8; 32],
    invoice_expiry_delta_secs: u32,
    current_time: u64,
    min_final_cltv_expiry_delta: Option<u16>,
) -> Result<[u8; 32], VlsAdapterError> {
    let metadata_bytes = construct_metadata_bytes_local(
        min_value_msat,
        if min_final_cltv_expiry_delta.is_some() {
            InboundMethod::UserPaymentHashCustomFinalCltv
        } else {
            InboundMethod::UserPaymentHash
        },
        invoice_expiry_delta_secs,
        current_time,
        min_final_cltv_expiry_delta,
    )?;
    let mut hmac = HmacEngine::<Sha256>::new(&keys.user_pmt_hash_key);
    hmac.input(&metadata_bytes);
    hmac.input(&payment_hash);
    let hmac_bytes = bitcoin::hashes::hmac::Hmac::<Sha256>::from_engine(hmac).to_byte_array();
    let mut iv_bytes = [0u8; INBOUND_IV_LEN];
    iv_bytes.copy_from_slice(&hmac_bytes[..INBOUND_IV_LEN]);
    Ok(construct_payment_secret_local(
        &iv_bytes,
        &metadata_bytes,
        &keys.metadata_key,
    ))
}

fn create_spontaneous_payment_secret_local(
    keys: &ExpandedInboundKeys,
    min_value_msat: Option<u64>,
    invoice_expiry_delta_secs: u32,
    current_time: u64,
    min_final_cltv_expiry_delta: Option<u16>,
) -> Result<[u8; 32], VlsAdapterError> {
    let metadata_bytes = construct_metadata_bytes_local(
        min_value_msat,
        InboundMethod::SpontaneousPayment,
        invoice_expiry_delta_secs,
        current_time,
        min_final_cltv_expiry_delta,
    )?;
    let mut hmac = HmacEngine::<Sha256>::new(&keys.spontaneous_pmt_key);
    hmac.input(&metadata_bytes);
    let hmac_bytes = bitcoin::hashes::hmac::Hmac::<Sha256>::from_engine(hmac).to_byte_array();
    let mut iv_bytes = [0u8; INBOUND_IV_LEN];
    iv_bytes.copy_from_slice(&hmac_bytes[..INBOUND_IV_LEN]);
    Ok(construct_payment_secret_local(
        &iv_bytes,
        &metadata_bytes,
        &keys.metadata_key,
    ))
}

fn verify_inbound_payment_local(
    keys: &ExpandedInboundKeys,
    payment_hash: [u8; 32],
    payment_secret: [u8; 32],
    total_msat: u64,
    highest_seen_timestamp: u64,
) -> Result<(Option<[u8; 32]>, Option<u16>), VlsAdapterError> {
    let (iv_bytes, metadata_bytes) = decrypt_metadata_local(payment_secret, keys);
    let payment_type =
        InboundMethod::from_bits((metadata_bytes[0] & 0b1110_0000) >> INBOUND_METHOD_TYPE_OFFSET)?;

    let mut amt_msat_bytes = [0u8; INBOUND_AMT_MSAT_LEN];
    let mut expiry_bytes = [0u8; INBOUND_METADATA_LEN - INBOUND_AMT_MSAT_LEN];
    amt_msat_bytes.copy_from_slice(&metadata_bytes[..INBOUND_AMT_MSAT_LEN]);
    expiry_bytes.copy_from_slice(&metadata_bytes[INBOUND_AMT_MSAT_LEN..]);
    amt_msat_bytes[0] &= 0b0001_1111;

    let payment_preimage = match payment_type {
        InboundMethod::UserPaymentHash | InboundMethod::UserPaymentHashCustomFinalCltv => {
            let mut hmac = HmacEngine::<Sha256>::new(&keys.user_pmt_hash_key);
            hmac.input(&metadata_bytes);
            hmac.input(&payment_hash);
            let expected = bitcoin::hashes::hmac::Hmac::<Sha256>::from_engine(hmac).to_byte_array();
            if !fixed_time_eq(&iv_bytes, &expected[..INBOUND_IV_LEN]) {
                return Err(VlsAdapterError::Protocol(
                    "verify inbound payment failed".to_string(),
                ));
            }
            None
        }
        InboundMethod::LdkPaymentHash | InboundMethod::LdkPaymentHashCustomFinalCltv => {
            Some(
                derive_ldk_payment_preimage_local(payment_hash, &iv_bytes, &metadata_bytes, keys)
                    .map_err(|_| {
                        VlsAdapterError::Protocol("verify inbound payment failed".to_string())
                    })?,
            )
        }
        InboundMethod::SpontaneousPayment => {
            let mut hmac = HmacEngine::<Sha256>::new(&keys.spontaneous_pmt_key);
            hmac.input(&metadata_bytes);
            let expected = bitcoin::hashes::hmac::Hmac::<Sha256>::from_engine(hmac).to_byte_array();
            if !fixed_time_eq(&iv_bytes, &expected[..INBOUND_IV_LEN]) {
                return Err(VlsAdapterError::Protocol(
                    "verify inbound payment failed".to_string(),
                ));
            }
            None
        }
    };

    let min_final_cltv_expiry_delta = match payment_type {
        InboundMethod::UserPaymentHashCustomFinalCltv
        | InboundMethod::LdkPaymentHashCustomFinalCltv => {
            let delta = min_final_cltv_expiry_delta_from_metadata_local(metadata_bytes);
            expiry_bytes[0] = 0;
            expiry_bytes[1] = 0;
            Some(delta)
        }
        _ => None,
    };

    let min_amt_msat = u64::from_be_bytes(amt_msat_bytes);
    let expiry = u64::from_be_bytes(expiry_bytes);
    if total_msat < min_amt_msat || expiry < highest_seen_timestamp {
        return Err(VlsAdapterError::Protocol(
            "verify inbound payment failed".to_string(),
        ));
    }
    Ok((payment_preimage, min_final_cltv_expiry_delta))
}

fn get_payment_preimage_local(
    keys: &ExpandedInboundKeys,
    payment_hash: [u8; 32],
    payment_secret: [u8; 32],
) -> Result<[u8; 32], VlsAdapterError> {
    let (iv_bytes, metadata_bytes) = decrypt_metadata_local(payment_secret, keys);
    match InboundMethod::from_bits((metadata_bytes[0] & 0b1110_0000) >> INBOUND_METHOD_TYPE_OFFSET)? {
        InboundMethod::LdkPaymentHash | InboundMethod::LdkPaymentHashCustomFinalCltv => {
            derive_ldk_payment_preimage_local(payment_hash, &iv_bytes, &metadata_bytes, keys)
                .map_err(|_| {
                    VlsAdapterError::Protocol("get payment preimage failed".to_string())
                })
        }
        InboundMethod::UserPaymentHash | InboundMethod::UserPaymentHashCustomFinalCltv => Err(
            VlsAdapterError::Protocol(
                "expected LdkPaymentHash, got UserPaymentHash".to_string(),
            ),
        ),
        InboundMethod::SpontaneousPayment => Err(VlsAdapterError::Protocol(
            "can't extract payment preimage for spontaneous payments".to_string(),
        )),
    }
}

fn derive_ldk_auxiliary_keys_hex_from_seed(
    seed: &[u8; 32],
) -> Result<(String, String, String), VlsAdapterError> {
    let (a, b, c) = crate::ldk_keys_manager_material::derive_ldk_keys_manager_auxiliary_secret_bytes(seed)
        .map_err(|e| VlsAdapterError::Protocol(format!("derive LDK auxiliary keys: {e}")))?;
    Ok((hex::encode(a), hex::encode(b), hex::encode(c)))
}

fn derive_async_payments_hashes_from_seed(
    seed: &[u8; 32],
    network: bitcoin::Network,
    host_node_id_hex: &str,
    start_index: u64,
    batch_size: u32,
) -> Result<Vec<AsyncPaymentsHashEntry>, VlsAdapterError> {
    use bitcoin::bip32::{ChildNumber, DerivationPath, Xpriv};
    use bitcoin::secp256k1::PublicKey;

    const ASYNC_ORDER_FIRST_HASH_INDEX: u64 = 1;
    const ASYNC_PAYMENTS_ACCOUNT_INDEX: u32 = 0;
    const ASYNC_PAYMENTS_BIP32_MAX_CHILD_INDEX: u32 = 0x7fff_ffff;
    const ASYNC_PAYMENTS_PREIMAGE_DOMAIN: &[u8] = b"async-payments/v0";
    const ASYNC_PAYMENTS_PURPOSE_APAY_INDEX: u32 = 0x4150_4159;

    if start_index < ASYNC_ORDER_FIRST_HASH_INDEX || batch_size == 0 {
        return Err(VlsAdapterError::Protocol(
            "invalid async payments hash batch".to_string(),
        ));
    }
    let last_index = start_index
        .checked_add(batch_size as u64 - 1)
        .ok_or_else(|| VlsAdapterError::Protocol("invalid async payments hash batch".to_string()))?;
    if last_index > ASYNC_PAYMENTS_BIP32_MAX_CHILD_INDEX as u64 {
        return Err(VlsAdapterError::Protocol(
            "invalid async payments hash batch".to_string(),
        ));
    }

    let host_node_id = PublicKey::from_slice(
        &hex::decode(host_node_id_hex)
            .map_err(|e| VlsAdapterError::Protocol(format!("invalid host_node_id hex: {e}")))?,
    )
    .map_err(|e| VlsAdapterError::Protocol(format!("invalid host_node_id pubkey: {e}")))?;

    let secp = bitcoin::secp256k1::Secp256k1::new();
    let mut account_xprv = Xpriv::new_master(network, seed)
        .map_err(|e| VlsAdapterError::Protocol(format!("async payment root derivation failed: {e}")))?;
    let h31 = u32::from_be_bytes(
        bitcoin::hashes::sha256::Hash::hash(&host_node_id.serialize()).to_byte_array()[0..4]
            .try_into()
            .expect("sha256 is 32 bytes"),
    ) & ASYNC_PAYMENTS_BIP32_MAX_CHILD_INDEX;
    let account_path = DerivationPath::from(vec![
        ChildNumber::Hardened {
            index: ASYNC_PAYMENTS_PURPOSE_APAY_INDEX,
        },
        ChildNumber::Hardened {
            index: ASYNC_PAYMENTS_ACCOUNT_INDEX,
        },
        ChildNumber::Hardened { index: h31 },
    ]);
    account_xprv = account_xprv
        .derive_priv(&secp, &account_path)
        .map_err(|e| VlsAdapterError::Protocol(format!("async payment root derivation failed: {e}")))?;

    let mut hashes = Vec::with_capacity(batch_size as usize);
    for hash_index in start_index..=last_index {
        let child_xprv = account_xprv
            .derive_priv(
                &secp,
                &DerivationPath::from(vec![ChildNumber::Hardened {
                    index: hash_index as u32,
                }]),
            )
            .map_err(|e| VlsAdapterError::Protocol(format!("async payment child derivation failed: {e}")))?;
        let child_secret = child_xprv.private_key.secret_bytes();
        let mut preimage_material =
            Vec::with_capacity(ASYNC_PAYMENTS_PREIMAGE_DOMAIN.len() + child_secret.len());
        preimage_material.extend_from_slice(ASYNC_PAYMENTS_PREIMAGE_DOMAIN);
        preimage_material.extend_from_slice(&child_secret);
        let payment_preimage =
            bitcoin::hashes::sha256::Hash::hash(&preimage_material).to_byte_array();
        let payment_hash =
            bitcoin::hashes::sha256::Hash::hash(&payment_preimage).to_byte_array();
        hashes.push(AsyncPaymentsHashEntry {
            hash_index,
            payment_hash_hex: hex::encode(payment_hash),
        });
    }

    Ok(hashes)
}

#[cfg(feature = "with-vls")]
fn derive_ldk_destination_script_hex_from_seed(
    seed: &[u8; 32],
    network: bitcoin::Network,
) -> Result<String, VlsAdapterError> {
    use bitcoin::bip32::ChildNumber;
    use bitcoin::secp256k1::Secp256k1;
    use bitcoin::{Address, CompressedPublicKey};
    use lightning_signer::signer::derive::KeyDerivationStyle;
    use lightning_signer::signer::{my_keys_manager::MyKeysManager, ClockStartingTimeFactory};

    const DESTINATION_SCRIPT_INDEX: ChildNumber = ChildNumber::Normal { index: 1 };

    let secp = Secp256k1::new();
    let starting_time_factory = ClockStartingTimeFactory {};
    let manager = MyKeysManager::new(KeyDerivationStyle::Ldk, seed, network, &starting_time_factory);
    let account_extended_key = manager.get_account_extended_key().clone();
    let destination_key = account_extended_key
        .derive_priv(&secp, &[DESTINATION_SCRIPT_INDEX])
        .map_err(|e| VlsAdapterError::Protocol(format!("derive destination child key: {e}")))?;
    Ok(hex::encode(
        Address::p2wpkh(
            &CompressedPublicKey::from_slice(
                &destination_key.private_key.public_key(&secp).serialize(),
            )
            .map_err(|e| VlsAdapterError::Protocol(format!("invalid destination pubkey: {e}")))?,
            network,
        )
        .script_pubkey()
        .as_bytes(),
    ))
}

#[cfg(feature = "with-vls")]
fn derive_ldk_shutdown_script_hex_from_seed(
    seed: &[u8; 32],
    network: bitcoin::Network,
) -> Result<String, VlsAdapterError> {
    use lightning_signer::lightning::sign::SignerProvider;
    use lightning_signer::signer::derive::KeyDerivationStyle;
    use lightning_signer::signer::{my_keys_manager::MyKeysManager, ClockStartingTimeFactory};

    let starting_time_factory = ClockStartingTimeFactory {};
    let manager = MyKeysManager::new(KeyDerivationStyle::Ldk, seed, network, &starting_time_factory);
    Ok(hex::encode(
        manager
            .get_shutdown_scriptpubkey()
            .map_err(|_| VlsAdapterError::Protocol("get shutdown script from MyKeysManager".into()))?
            .into_inner()
            .as_bytes(),
    ))
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
    fn node_encrypt_peer_storage_payload(
        &self,
        plaintext_hex: String,
        random_bytes_hex: String,
    ) -> Result<String, VlsAdapterError>;
    fn node_decrypt_peer_storage_payload(
        &self,
        ciphertext_hex: String,
    ) -> Result<String, VlsAdapterError>;
    fn node_encrypt_blinded_message_payload(
        &self,
        plaintext_hex: String,
        rho_hex: String,
    ) -> Result<String, VlsAdapterError>;
    fn node_decrypt_blinded_message_payload(
        &self,
        ciphertext_hex: String,
        rho_hex: String,
    ) -> Result<(String, bool), VlsAdapterError>;
    fn node_get_hmac_for_offer_key(&self) -> Result<String, VlsAdapterError>;
    fn node_crypt_for_offer(
        &self,
        bytes_hex: String,
        nonce_hex: String,
    ) -> Result<String, VlsAdapterError>;
    fn node_create_inbound_payment(
        &self,
        min_value_msat: Option<u64>,
        invoice_expiry_delta_secs: u32,
        random_bytes_hex: String,
        current_time: u64,
        min_final_cltv_expiry_delta: Option<u16>,
    ) -> Result<(String, String), VlsAdapterError>;
    fn node_create_inbound_payment_for_hash(
        &self,
        payment_hash_hex: String,
        min_value_msat: Option<u64>,
        invoice_expiry_delta_secs: u32,
        current_time: u64,
        min_final_cltv_expiry_delta: Option<u16>,
    ) -> Result<String, VlsAdapterError>;
    fn node_create_spontaneous_payment_secret(
        &self,
        min_value_msat: Option<u64>,
        invoice_expiry_delta_secs: u32,
        current_time: u64,
        min_final_cltv_expiry_delta: Option<u16>,
    ) -> Result<String, VlsAdapterError>;
    fn node_verify_inbound_payment(
        &self,
        payment_hash_hex: String,
        payment_secret_hex: String,
        total_msat: u64,
        highest_seen_timestamp: u64,
    ) -> Result<(Option<String>, Option<u16>), VlsAdapterError>;
    fn node_get_payment_preimage(
        &self,
        payment_hash_hex: String,
        payment_secret_hex: String,
    ) -> Result<String, VlsAdapterError>;
    fn node_prepare_async_payments_hashes(
        &self,
        host_node_id_hex: String,
        start_index: u64,
        batch_size: u32,
    ) -> Result<Vec<AsyncPaymentsHashEntry>, VlsAdapterError>;

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
        inputs: Vec<SpendableOutputSignInput>,
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

    fn find_derivation_matches(
        &self,
        script_pubkey_hex: String,
        max_index: u32,
    ) -> Result<Vec<DerivedAddressMatch>, VlsAdapterError>;
}

/// VLS wire mapping: `crate::contract::ChannelOp` → `vls-protocol` messages.
///
/// **Holder commitment** (`ChannelOp::ValidateHolderCommitment`):
/// - If `commitment_unsigned_tx_hex` is missing, empty, or whitespace only → **`ValidateCommitmentTx2`**
///   (LDK summary fields only).
/// - Otherwise → try **`ValidateCommitmentTx`** on the wire transaction; if VLS rejects it (for
///   example unsigned P2WSH outputs without embedded `witness_script` in the PSBT), fall back to
///   **`ValidateCommitmentTx2`** so native external signers still enforce balances on RGB channels.
#[cfg(feature = "with-vls")]
pub mod vls_real {
    use super::*;
    use crate::contract::{SpendableDescriptorKind, SpendableOutputSignInput};
    use base64::Engine;
    use bitcoin::bip32::{ChildNumber, DerivationPath, Fingerprint, Xpriv, Xpub};
    use bitcoin::consensus::deserialize as consensus_deserialize_tx;
    use bitcoin::psbt::Psbt;
    use bitcoin::secp256k1::ecdsa::Signature;
    use bitcoin::secp256k1::Secp256k1;
    use bitcoin::sighash::EcdsaSighashType;
    use bitcoin::Network;
    use bitcoin::Txid;
    use bitcoin::{Address, CompressedPublicKey, ScriptBuf};
    use lightning_signer::channel::{ChannelId, CommitmentType};
    use lightning_signer::lightning::sign::{ChannelSigner as _, SignerProvider};
    use lightning_signer::signer::my_keys_manager::MyKeysManager;
    use lightning_signer::signer::{derive::KeyDerivationStyle, ClockStartingTimeFactory};
    use serde::{Deserialize, Serialize};
    use std::str::FromStr;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    use vls_protocol::model::{Basepoints, BitcoinSignature, CloseInfo, PubKey, Utxo};
    use vls_protocol::msgs::{
        Ecdh, EcdhReply, GetChannelBasepoints, GetChannelBasepointsReply, GetPerCommitmentPoint,
        GetPerCommitmentPoint2, GetPerCommitmentPoint2Reply, GetPerCommitmentPointReply, HsmdInit2,
        HsmdInit2Reply, NewChannel, NewChannelReply, SetupChannel, SetupChannelReply,
        SignCommitmentTxReply, SignCommitmentTxWithHtlcsReply, SignGossipMessage,
        SignGossipMessageReply, SignInvoice, SignInvoiceReply, SignLocalCommitmentTx2, SignMessage,
        SignMessageReply, SignMutualCloseTx, SignRemoteCommitmentTx, SignRemoteCommitmentTx2,
        SignTxReply, SignWithdrawal, SignWithdrawalReply, ValidateCommitmentTx,
        ValidateCommitmentTx2, ValidateCommitmentTxReply,
    };
    use vls_protocol::psbt::{PsbtWrapper, StreamedPSBT};
    use vls_protocol::serde_bolt::{Array, Octets, WireString, WithSize};
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

    fn spendable_sign_input_to_vls_model(
        input: SpendableOutputSignInput,
    ) -> Result<Utxo, VlsAdapterError> {
        let txid = Txid::from_str(&input.txid_hex).map_err(|e| {
            VlsAdapterError::Protocol(format!("invalid spendable input txid_hex: {e}"))
        })?;
        let script = if input.script_pubkey_hex.is_empty() {
            Octets::EMPTY
        } else {
            Octets(hex::decode(&input.script_pubkey_hex).map_err(|e| {
                VlsAdapterError::Protocol(format!("invalid spendable input script_pubkey_hex: {e}"))
            })?)
        };

        let (keyindex, close_info) = match input.descriptor_kind {
            SpendableDescriptorKind::StaticOutput => (
                input
                    .wallet_derivation_match
                    .as_ref()
                    .map(|m| m.keyindex)
                    .unwrap_or(0),
                None,
            ),
            SpendableDescriptorKind::StaticPaymentOutput => {
                let channel_keys_id_hex = input.channel_keys_id_hex.ok_or_else(|| {
                    VlsAdapterError::Protocol(
                        "missing channel_keys_id_hex for StaticPaymentOutput".to_string(),
                    )
                })?;
                let dbid = RealVlsClient::channel_keys_id_hex_to_dbid(&channel_keys_id_hex)?;
                let peer_id = RealVlsClient::default_peer_id();
                (
                    0,
                    Some(CloseInfo {
                        channel_id: dbid,
                        peer_id: PubKey(peer_id),
                        commitment_point: None,
                        is_anchors: false,
                        csv: 0,
                    }),
                )
            }
            SpendableDescriptorKind::DelayedPaymentOutput => {
                let channel_keys_id_hex = input.channel_keys_id_hex.ok_or_else(|| {
                    VlsAdapterError::Protocol(
                        "missing channel_keys_id_hex for DelayedPaymentOutput".to_string(),
                    )
                })?;
                let per_commitment_point_hex = input.per_commitment_point_hex.ok_or_else(|| {
                    VlsAdapterError::Protocol(
                        "missing per_commitment_point_hex for DelayedPaymentOutput".to_string(),
                    )
                })?;
                let point_bytes = hex::decode(&per_commitment_point_hex).map_err(|e| {
                    VlsAdapterError::Protocol(format!(
                        "invalid per_commitment_point_hex for DelayedPaymentOutput: {e}"
                    ))
                })?;
                let point_arr: [u8; 33] = point_bytes.try_into().map_err(|_| {
                    VlsAdapterError::Protocol(
                        "per_commitment_point_hex must decode to 33 bytes".to_string(),
                    )
                })?;
                let dbid = RealVlsClient::channel_keys_id_hex_to_dbid(&channel_keys_id_hex)?;
                let peer_id = RealVlsClient::default_peer_id();
                (
                    0,
                    Some(CloseInfo {
                        channel_id: dbid,
                        peer_id: PubKey(peer_id),
                        commitment_point: Some(PubKey(point_arr)),
                        is_anchors: false,
                        csv: input.to_self_delay.unwrap_or_default() as u32,
                    }),
                )
            }
        };

        Ok(Utxo {
            txid,
            outnum: input.vout,
            amount: input.amount_sat,
            keyindex,
            is_p2sh: false,
            script,
            close_info,
            is_in_coinbase: false,
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

        fn derive_stub_per_commitment_point(
            &self,
            dbid: u64,
            commitment_number: u64,
        ) -> Result<Option<String>, VlsAdapterError> {
            let Some(seed) = self.seed else {
                return Ok(None);
            };
            let network = Network::from_str(self.network()).map_err(|e| {
                VlsAdapterError::Protocol(format!("invalid network in adapter: {e}"))
            })?;
            let channel_id = ChannelId::new_from_peer_id_and_oid(&Self::default_peer_id(), dbid);
            let starting_time_factory = ClockStartingTimeFactory {};
            let manager = MyKeysManager::new(
                KeyDerivationStyle::Ldk,
                &seed,
                network,
                &starting_time_factory,
            );
            let signer = manager.derive_channel_signer(0, channel_id.ldk_channel_keys_id());
            let point = signer
                .get_per_commitment_point(
                    Self::LDK_INITIAL_COMMITMENT_NUMBER.saturating_sub(commitment_number),
                    &Secp256k1::new(),
                )
                .map_err(|_| {
                    VlsAdapterError::Transport(
                        "failed to synthesize pre-setup commitment point".to_string(),
                    )
                })?;
            Ok(Some(hex::encode(point.serialize())))
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

        fn mutual_close_wallet_path() -> Result<DerivationPath, VlsAdapterError> {
            Ok(DerivationPath::from(vec![ChildNumber::from_normal_idx(2)
                .map_err(|e| {
                    VlsAdapterError::Protocol(format!("invalid wallet path: {e}"))
                })?]))
        }

        fn attach_mutual_close_output_paths(
            psbt: &mut Psbt,
            holder_shutdown_script: &ScriptBuf,
        ) -> Result<(), VlsAdapterError> {
            let wallet_path = Self::mutual_close_wallet_path()?;
            let marker_secret = bitcoin::secp256k1::SecretKey::from_slice(&[1u8; 32])
                .map_err(|e| VlsAdapterError::Protocol(format!("invalid marker secret: {e}")))?;
            let marker_pubkey =
                bitcoin::secp256k1::PublicKey::from_secret_key(&Secp256k1::new(), &marker_secret);
            for (idx, output) in psbt.outputs.iter_mut().enumerate() {
                let script_pubkey = &psbt.unsigned_tx.output[idx].script_pubkey;
                if script_pubkey.is_op_return() || script_pubkey != holder_shutdown_script {
                    continue;
                }
                output.tap_key_origins.clear();
                output.bip32_derivation.clear();
                output
                    .bip32_derivation
                    .insert(marker_pubkey, (Fingerprint::default(), wallet_path.clone()));
            }
            Ok(())
        }

        fn populate_psbt_witness_utxos_from_sign_inputs(
            psbt: &mut Psbt,
            spendable_inputs: &[SpendableOutputSignInput],
        ) -> Result<(), VlsAdapterError> {
            for (idx, input) in psbt.inputs.iter_mut().enumerate() {
                if input.witness_utxo.is_some() {
                    continue;
                }
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
                let metadata = spendable_inputs
                    .iter()
                    .find(|utxo| {
                        utxo.txid_hex == prevout.txid.to_string() && utxo.vout == prevout.vout
                    })
                    .ok_or_else(|| {
                        VlsAdapterError::Protocol(format!(
                            "missing spendable metadata for psbt input {}:{}",
                            prevout.txid, prevout.vout
                        ))
                    })?;
                let script_pubkey =
                    ScriptBuf::from_hex(&metadata.script_pubkey_hex).map_err(|e| {
                        VlsAdapterError::Protocol(format!(
                            "invalid spendable input script_pubkey_hex for {}:{}: {e}",
                            metadata.txid_hex, metadata.vout
                        ))
                    })?;
                input.witness_utxo = Some(bitcoin::TxOut {
                    value: bitcoin::Amount::from_sat(metadata.amount_sat),
                    script_pubkey,
                });
            }
            Ok(())
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
            let destination_script_hex = self.node_get_destination_script(String::new())?;
            let destination_script = ScriptBuf::from_bytes(
                hex::decode(destination_script_hex).map_err(|e| {
                    VlsAdapterError::Protocol(format!("invalid destination script hex: {e}"))
                })?,
            );
            if *script == destination_script {
                return Ok(Some(1));
            }

            let shutdown_script_hex = self.node_get_shutdown_scriptpubkey()?;
            let shutdown_script = ScriptBuf::from_bytes(
                hex::decode(shutdown_script_hex).map_err(|e| {
                    VlsAdapterError::Protocol(format!("invalid shutdown script hex: {e}"))
                })?,
            );
            if *script == shutdown_script {
                return Ok(Some(2));
            }

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
        ) -> Result<Vec<DerivedAddressMatch>, VlsAdapterError> {
            let destination_script_hex = self.node_get_destination_script(String::new())?;
            let destination_script = ScriptBuf::from_bytes(
                hex::decode(destination_script_hex).map_err(|e| {
                    VlsAdapterError::Protocol(format!("invalid destination script hex: {e}"))
                })?,
            );
            let shutdown_script_hex = self.node_get_shutdown_scriptpubkey()?;
            let shutdown_script = ScriptBuf::from_bytes(
                hex::decode(shutdown_script_hex).map_err(|e| {
                    VlsAdapterError::Protocol(format!("invalid shutdown script hex: {e}"))
                })?,
            );
            let mut out = Vec::new();
            if *script == destination_script {
                out.push(DerivedAddressMatch {
                    keyindex: 1,
                    address: String::new(),
                    derivation_path: "1".to_string(),
                    account_name: "destination".to_string(),
                });
            }
            if *script == shutdown_script {
                out.push(DerivedAddressMatch {
                    keyindex: 2,
                    address: String::new(),
                    derivation_path: "2".to_string(),
                    account_name: "shutdown".to_string(),
                });
            }

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
                        out.push(DerivedAddressMatch {
                            keyindex: idx,
                            address: one_level_p2wpkh.to_string(),
                            derivation_path: format!("{idx}"),
                            account_name: account_name.to_string(),
                        });
                    }
                    let (one_level_xonly, _) = one_level.public_key.x_only_public_key();
                    let one_level_p2tr = Address::p2tr(&secp, one_level_xonly, None, network);
                    if one_level_p2tr.script_pubkey() == *script {
                        out.push(DerivedAddressMatch {
                            keyindex: idx,
                            address: one_level_p2tr.to_string(),
                            derivation_path: format!("{idx}"),
                            account_name: account_name.to_string(),
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
                            out.push(DerivedAddressMatch {
                                keyindex: idx,
                                address: p2wpkh.to_string(),
                                derivation_path: format!("{branch}/{idx}"),
                                account_name: account_name.to_string(),
                            });
                        }
                        let (xonly, _) = child.public_key.x_only_public_key();
                        let p2tr = Address::p2tr(&secp, xonly, None, network);
                        if p2tr.script_pubkey() == *script {
                            out.push(DerivedAddressMatch {
                                keyindex: idx,
                                address: p2tr.to_string(),
                                derivation_path: format!("{branch}/{idx}"),
                                account_name: account_name.to_string(),
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

            Ok(BootstrapData {
                identity: SignerIdentity {
                    node_id,
                    account_xpub_vanilla: xpub_vanilla,
                    account_xpub_colored: xpub_colored,
                    master_fingerprint,
                },
                protocol_version: "vls-protocol/0.14".to_string(),
                api_level: 1,
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
            _channel_keys_id_hex: String,
        ) -> Result<String, VlsAdapterError> {
            let seed = self.seed.ok_or_else(|| {
                VlsAdapterError::Protocol(
                    "RealVlsClient requires Some(seed) in new_with_network_and_seed so destination script can be derived".into(),
                )
            })?;
            let network = Network::from_str(self.network()).map_err(|e| {
                VlsAdapterError::Protocol(format!("invalid network in adapter: {e}"))
            })?;
            derive_ldk_destination_script_hex_from_seed(&seed, network)
        }

        fn node_get_shutdown_scriptpubkey(&self) -> Result<String, VlsAdapterError> {
            let seed = self.seed.ok_or_else(|| {
                VlsAdapterError::Protocol(
                    "RealVlsClient requires Some(seed) in new_with_network_and_seed so shutdown script can be derived".into(),
                )
            })?;
            let network = Network::from_str(self.network()).map_err(|e| {
                VlsAdapterError::Protocol(format!("invalid network in adapter: {e}"))
            })?;
            derive_ldk_shutdown_script_hex_from_seed(&seed, network)
        }

        fn node_get_secure_random_bytes(&self) -> Result<String, VlsAdapterError> {
            Ok(hex::encode([0u8; 32]))
        }

        fn node_encrypt_peer_storage_payload(
            &self,
            plaintext_hex: String,
            random_bytes_hex: String,
        ) -> Result<String, VlsAdapterError> {
            let seed = self.seed.ok_or_else(|| {
                VlsAdapterError::Protocol(
                    "RealVlsClient requires Some(seed) in new_with_network_and_seed so peer storage key can be derived".into(),
                )
            })?;
            let (_, peer_storage_key, _) = derive_ldk_auxiliary_keys_hex_from_seed(&seed)?;
            encrypt_peer_storage_payload_local(
                &peer_storage_key,
                plaintext_hex,
                random_bytes_hex,
            )
        }

        fn node_decrypt_peer_storage_payload(
            &self,
            ciphertext_hex: String,
        ) -> Result<String, VlsAdapterError> {
            let seed = self.seed.ok_or_else(|| {
                VlsAdapterError::Protocol(
                    "RealVlsClient requires Some(seed) in new_with_network_and_seed so peer storage key can be derived".into(),
                )
            })?;
            let (_, peer_storage_key, _) = derive_ldk_auxiliary_keys_hex_from_seed(&seed)?;
            decrypt_peer_storage_payload_local(&peer_storage_key, ciphertext_hex)
        }

        fn node_encrypt_blinded_message_payload(
            &self,
            plaintext_hex: String,
            rho_hex: String,
        ) -> Result<String, VlsAdapterError> {
            let seed = self.seed.ok_or_else(|| {
                VlsAdapterError::Protocol(
                    "RealVlsClient requires Some(seed) in new_with_network_and_seed so receive auth key can be derived".into(),
                )
            })?;
            let (_, _, receive_auth_key) = derive_ldk_auxiliary_keys_hex_from_seed(&seed)?;
            encrypt_blinded_message_payload_local(&receive_auth_key, plaintext_hex, rho_hex)
        }

        fn node_decrypt_blinded_message_payload(
            &self,
            ciphertext_hex: String,
            rho_hex: String,
        ) -> Result<(String, bool), VlsAdapterError> {
            let seed = self.seed.ok_or_else(|| {
                VlsAdapterError::Protocol(
                    "RealVlsClient requires Some(seed) in new_with_network_and_seed so receive auth key can be derived".into(),
                )
            })?;
            let (_, _, receive_auth_key) = derive_ldk_auxiliary_keys_hex_from_seed(&seed)?;
            decrypt_blinded_message_payload_local(&receive_auth_key, ciphertext_hex, rho_hex)
        }

        fn node_get_hmac_for_offer_key(&self) -> Result<String, VlsAdapterError> {
            let seed = self.seed.ok_or_else(|| {
                VlsAdapterError::Protocol(
                    "RealVlsClient requires Some(seed) in new_with_network_and_seed so offer key can be derived".into(),
                )
            })?;
            let (inbound, _, _) = derive_ldk_auxiliary_keys_hex_from_seed(&seed)?;
            let (offers_base_key, _) = offer_keys_from_inbound_key_hex(&inbound)?;
            Ok(hex::encode(offers_base_key))
        }

        fn node_crypt_for_offer(
            &self,
            bytes_hex: String,
            nonce_hex: String,
        ) -> Result<String, VlsAdapterError> {
            let seed = self.seed.ok_or_else(|| {
                VlsAdapterError::Protocol(
                    "RealVlsClient requires Some(seed) in new_with_network_and_seed so offer crypto can be derived".into(),
                )
            })?;
            let (inbound, _, _) = derive_ldk_auxiliary_keys_hex_from_seed(&seed)?;
            crypt_for_offer_local(&inbound, bytes_hex, nonce_hex)
        }

        fn node_create_inbound_payment(
            &self,
            min_value_msat: Option<u64>,
            invoice_expiry_delta_secs: u32,
            random_bytes_hex: String,
            current_time: u64,
            min_final_cltv_expiry_delta: Option<u16>,
        ) -> Result<(String, String), VlsAdapterError> {
            let seed = self.seed.ok_or_else(|| {
                VlsAdapterError::Protocol(
                    "RealVlsClient requires Some(seed) in new_with_network_and_seed so inbound payment material can be derived".into(),
                )
            })?;
            let (inbound, _, _) = derive_ldk_auxiliary_keys_hex_from_seed(&seed)?;
            let expanded = expanded_keys_from_inbound_key_hex(&inbound)?;
            let random_bytes = hex::decode(random_bytes_hex).map_err(|e| {
                VlsAdapterError::Protocol(format!("invalid random_bytes_hex: {e}"))
            })?;
            let random_bytes: [u8; 32] = random_bytes.try_into().map_err(|_| {
                VlsAdapterError::Protocol("random_bytes_hex must decode to 32 bytes".to_string())
            })?;
            let (payment_hash, payment_secret) = create_inbound_payment_local(
                &expanded,
                min_value_msat,
                invoice_expiry_delta_secs,
                random_bytes,
                current_time,
                min_final_cltv_expiry_delta,
            )?;
            Ok((hex::encode(payment_hash), hex::encode(payment_secret)))
        }

        fn node_create_inbound_payment_for_hash(
            &self,
            payment_hash_hex: String,
            min_value_msat: Option<u64>,
            invoice_expiry_delta_secs: u32,
            current_time: u64,
            min_final_cltv_expiry_delta: Option<u16>,
        ) -> Result<String, VlsAdapterError> {
            let seed = self.seed.ok_or_else(|| {
                VlsAdapterError::Protocol(
                    "RealVlsClient requires Some(seed) in new_with_network_and_seed so inbound payment material can be derived".into(),
                )
            })?;
            let (inbound, _, _) = derive_ldk_auxiliary_keys_hex_from_seed(&seed)?;
            let expanded = expanded_keys_from_inbound_key_hex(&inbound)?;
            let payment_hash = hex::decode(payment_hash_hex).map_err(|e| {
                VlsAdapterError::Protocol(format!("invalid payment_hash_hex: {e}"))
            })?;
            let payment_hash: [u8; 32] = payment_hash.try_into().map_err(|_| {
                VlsAdapterError::Protocol("payment_hash_hex must decode to 32 bytes".to_string())
            })?;
            let payment_secret = create_inbound_payment_for_hash_local(
                &expanded,
                min_value_msat,
                payment_hash,
                invoice_expiry_delta_secs,
                current_time,
                min_final_cltv_expiry_delta,
            )?;
            Ok(hex::encode(payment_secret))
        }

        fn node_create_spontaneous_payment_secret(
            &self,
            min_value_msat: Option<u64>,
            invoice_expiry_delta_secs: u32,
            current_time: u64,
            min_final_cltv_expiry_delta: Option<u16>,
        ) -> Result<String, VlsAdapterError> {
            let seed = self.seed.ok_or_else(|| {
                VlsAdapterError::Protocol(
                    "RealVlsClient requires Some(seed) in new_with_network_and_seed so spontaneous-payment material can be derived".into(),
                )
            })?;
            let (inbound, _, _) = derive_ldk_auxiliary_keys_hex_from_seed(&seed)?;
            let expanded = expanded_keys_from_inbound_key_hex(&inbound)?;
            let payment_secret = create_spontaneous_payment_secret_local(
                &expanded,
                min_value_msat,
                invoice_expiry_delta_secs,
                current_time,
                min_final_cltv_expiry_delta,
            )?;
            Ok(hex::encode(payment_secret))
        }

        fn node_verify_inbound_payment(
            &self,
            payment_hash_hex: String,
            payment_secret_hex: String,
            total_msat: u64,
            highest_seen_timestamp: u64,
        ) -> Result<(Option<String>, Option<u16>), VlsAdapterError> {
            let seed = self.seed.ok_or_else(|| {
                VlsAdapterError::Protocol(
                    "RealVlsClient requires Some(seed) in new_with_network_and_seed so inbound payment material can be derived".into(),
                )
            })?;
            let (inbound, _, _) = derive_ldk_auxiliary_keys_hex_from_seed(&seed)?;
            let expanded = expanded_keys_from_inbound_key_hex(&inbound)?;
            let payment_hash = hex::decode(payment_hash_hex).map_err(|e| {
                VlsAdapterError::Protocol(format!("invalid payment_hash_hex: {e}"))
            })?;
            let payment_hash: [u8; 32] = payment_hash.try_into().map_err(|_| {
                VlsAdapterError::Protocol("payment_hash_hex must decode to 32 bytes".to_string())
            })?;
            let payment_secret = hex::decode(payment_secret_hex).map_err(|e| {
                VlsAdapterError::Protocol(format!("invalid payment_secret_hex: {e}"))
            })?;
            let payment_secret: [u8; 32] = payment_secret.try_into().map_err(|_| {
                VlsAdapterError::Protocol(
                    "payment_secret_hex must decode to 32 bytes".to_string(),
                )
            })?;
            let (preimage, min_final_cltv_expiry_delta) = verify_inbound_payment_local(
                &expanded,
                payment_hash,
                payment_secret,
                total_msat,
                highest_seen_timestamp,
            )?;
            Ok((preimage.map(hex::encode), min_final_cltv_expiry_delta))
        }

        fn node_get_payment_preimage(
            &self,
            payment_hash_hex: String,
            payment_secret_hex: String,
        ) -> Result<String, VlsAdapterError> {
            let seed = self.seed.ok_or_else(|| {
                VlsAdapterError::Protocol(
                    "RealVlsClient requires Some(seed) in new_with_network_and_seed so inbound payment material can be derived".into(),
                )
            })?;
            let (inbound, _, _) = derive_ldk_auxiliary_keys_hex_from_seed(&seed)?;
            let expanded = expanded_keys_from_inbound_key_hex(&inbound)?;
            let payment_hash = hex::decode(payment_hash_hex).map_err(|e| {
                VlsAdapterError::Protocol(format!("invalid payment_hash_hex: {e}"))
            })?;
            let payment_hash: [u8; 32] = payment_hash.try_into().map_err(|_| {
                VlsAdapterError::Protocol("payment_hash_hex must decode to 32 bytes".to_string())
            })?;
            let payment_secret = hex::decode(payment_secret_hex).map_err(|e| {
                VlsAdapterError::Protocol(format!("invalid payment_secret_hex: {e}"))
            })?;
            let payment_secret: [u8; 32] = payment_secret.try_into().map_err(|_| {
                VlsAdapterError::Protocol(
                    "payment_secret_hex must decode to 32 bytes".to_string(),
                )
            })?;
            let preimage = get_payment_preimage_local(&expanded, payment_hash, payment_secret)?;
            Ok(hex::encode(preimage))
        }

        fn node_prepare_async_payments_hashes(
            &self,
            host_node_id_hex: String,
            start_index: u64,
            batch_size: u32,
        ) -> Result<Vec<AsyncPaymentsHashEntry>, VlsAdapterError> {
            let seed = self.seed.ok_or_else(|| {
                VlsAdapterError::Protocol(
                    "RealVlsClient requires Some(seed) in new_with_network_and_seed so async payments hashes can be derived".into(),
                )
            })?;
            let network = Network::from_str(self.network()).map_err(|e| {
                VlsAdapterError::Protocol(format!("invalid network in adapter: {e}"))
            })?;
            derive_async_payments_hashes_from_seed(
                &seed,
                network,
                &host_node_id_hex,
                start_index,
                batch_size,
            )
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
                    let reply: Result<GetPerCommitmentPoint2Reply, VlsAdapterError> = call(
                        dbid,
                        PubKey(peer_id),
                        &*self.transport,
                        GetPerCommitmentPoint2 { commitment_number },
                    )
                    .map_err(|e| {
                        VlsAdapterError::Transport(format!(
                            "get_per_commitment_point failed: {e:?}"
                        ))
                    });
                    match reply {
                        Ok(reply) => Ok(ChannelResponse::PerCommitmentPoint {
                            point_hex: hex::encode(reply.point.0),
                        }),
                        Err(err) => {
                            if let Some(point_hex) =
                                self.derive_stub_per_commitment_point(dbid, commitment_number)?
                            {
                                tracing::warn!(
                                    dbid,
                                    commitment_number,
                                    error = %err,
                                    "falling back to synthesized pre-setup commitment point"
                                );
                                Ok(ChannelResponse::PerCommitmentPoint { point_hex })
                            } else {
                                Err(err)
                            }
                        }
                    }
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
                // See module doc on `vls_real` for the two-path rule.
                ChannelOp::ValidateHolderCommitment {
                    commitment_number,
                    feerate_sat_per_kw,
                    to_local_value_sat,
                    to_remote_value_sat,
                    htlcs,
                    counterparty_signature_hex,
                    counterparty_htlc_signatures_hex,
                    commitment_unsigned_tx_hex,
                    commitment_psbt_output_witness_scripts_hex,
                } => {
                    let htlc_models: Vec<vls_protocol::model::Htlc> = htlcs
                        .into_iter()
                        .map(|h| {
                            let payment_hash = hex::decode(&h.payment_hash_hex).map_err(|e| {
                                VlsAdapterError::Protocol(format!("invalid payment_hash_hex: {e}"))
                            })?;
                            let payment_hash: [u8; 32] = payment_hash.try_into().map_err(|_| {
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
                        .collect::<Result<Vec<_>, VlsAdapterError>>()?;
                    let htlcs_wire = Array(
                        htlc_models
                            .iter()
                            .map(|h| vls_protocol::model::Htlc {
                                side: h.side,
                                amount: h.amount,
                                payment_hash: h.payment_hash.clone(),
                                ctlv_expiry: h.ctlv_expiry,
                            })
                            .collect::<Vec<_>>(),
                    );
                    let htlcs_summary = Array(htlc_models);

                    let signature_wire = to_bitcoin_sig(&counterparty_signature_hex)?;
                    let signature_summary = to_bitcoin_sig(&counterparty_signature_hex)?;
                    let htlc_sig_vec: Vec<vls_protocol::model::BitcoinSignature> =
                        counterparty_htlc_signatures_hex
                            .iter()
                            .map(|s| to_bitcoin_sig(s))
                            .collect::<Result<Vec<_>, VlsAdapterError>>()?;
                    let htlc_signatures_wire = Array(
                        htlc_sig_vec
                            .iter()
                            .map(|s| vls_protocol::model::BitcoinSignature {
                                signature: s.signature.clone(),
                                sighash: s.sighash,
                            })
                            .collect::<Vec<_>>(),
                    );
                    let htlc_signatures_summary = Array(htlc_sig_vec);

                    let wire_validation_ok = if let Some(tx_hex) = commitment_unsigned_tx_hex
                        .as_ref()
                        .map(|s| s.trim())
                        .filter(|s| !s.is_empty())
                    {
                        let raw = hex::decode(tx_hex).map_err(|e| {
                            VlsAdapterError::Protocol(format!(
                                "validate_holder_commitment:rgb_wire_tx:invalid_hex: {e}"
                            ))
                        })?;
                        let tx: bitcoin::Transaction = consensus_deserialize_tx(&raw).map_err(
                            |e| {
                                VlsAdapterError::Protocol(format!(
                                    "validate_holder_commitment:rgb_wire_tx:invalid_consensus_tx: {e}"
                                ))
                            },
                        )?;
                        let mut psbt = Psbt::from_unsigned_tx(tx.clone()).map_err(|e| {
                            VlsAdapterError::Protocol(format!(
                                "validate_holder_commitment:rgb_wire_tx:psbt_from_unsigned_tx: {e}"
                            ))
                        })?;
                        if let Some(wits) = commitment_psbt_output_witness_scripts_hex.as_ref() {
                            if wits.len() != psbt.outputs.len() {
                                return Err(VlsAdapterError::Protocol(format!(
                                    "validate_holder_commitment:rgb_wire_tx:witness_scripts_len {} != psbt.outputs.len {}",
                                    wits.len(),
                                    psbt.outputs.len()
                                )));
                            }
                            for (i, wh) in wits.iter().enumerate() {
                                let t = wh.trim();
                                if t.is_empty() {
                                    continue;
                                }
                                let bytes = hex::decode(t).map_err(|e| {
                                    VlsAdapterError::Protocol(format!(
                                        "validate_holder_commitment:rgb_wire_tx:witness_script_hex[{i}]: {e}"
                                    ))
                                })?;
                                psbt.outputs[i].witness_script = Some(ScriptBuf::from_bytes(bytes));
                            }
                        }
                        match call::<ValidateCommitmentTx, ValidateCommitmentTxReply>(
                            dbid,
                            PubKey(peer_id),
                            &*self.transport,
                            ValidateCommitmentTx {
                                tx: WithSize(tx),
                                psbt: WithSize(PsbtWrapper::from(psbt)),
                                htlcs: htlcs_wire,
                                commitment_number,
                                feerate: feerate_sat_per_kw,
                                signature: signature_wire,
                                htlc_signatures: htlc_signatures_wire,
                            },
                        ) {
                            Ok(_) => true,
                            Err(e) => {
                                tracing::warn!(
                                    error = ?e,
                                    "VLS ValidateCommitmentTx failed on RGB holder wire tx; using ValidateCommitmentTx2 summary path"
                                );
                                false
                            }
                        }
                    } else {
                        false
                    };

                    if !wire_validation_ok {
                        let _: ValidateCommitmentTxReply = call(
                            dbid,
                            PubKey(peer_id),
                            &*self.transport,
                            ValidateCommitmentTx2 {
                                commitment_number,
                                feerate: feerate_sat_per_kw,
                                to_local_value_sat,
                                to_remote_value_sat,
                                htlcs: htlcs_summary,
                                signature: signature_summary,
                                htlc_signatures: htlc_signatures_summary,
                            },
                        )
                        .map_err(|e| {
                            VlsAdapterError::Transport(format!(
                                "validate_holder_commitment:summary:vls_validate_commitment_tx2: {e:?}"
                            ))
                        })?;
                    }
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
                    tx_hex,
                    remote_per_commitment_point_hex,
                    commitment_number,
                    feerate_sat_per_kw,
                    to_local_value_sat,
                    to_remote_value_sat,
                    htlcs,
                    commitment_psbt_output_witness_scripts_hex,
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
                    // `vls_protocol::serde_bolt::Array` doesn't implement `Clone`, so we rebuild it for
                    // each signing API call.
                    let htlcs_tx2 = Array(
                        htlcs
                            .iter()
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
                    let has_witness_scripts = commitment_psbt_output_witness_scripts_hex
                        .as_ref()
                        .is_some_and(|w| !w.is_empty());

                    // RGB-colored commitments can include extra outputs (e.g. `OP_RETURN`) so the
                    // wire transaction differs from VLS's vanilla recomposed commitment. Use the
                    // PSBT / witness-script path (`SignRemoteCommitmentTx`) so the **funding**
                    // signature is computed over the exact wire transaction. HTLC second-level
                    // signatures must use the wire commitment txid as well (see
                    // `InMemorySigner::sign_counterparty_commitment_htlc_signatures` in VLS core).
                    //
                    // Without witness scripts, `SignRemoteCommitmentTx2` (summary-only) is used.
                    if has_witness_scripts {
                        let raw = hex::decode(tx_hex.trim()).map_err(|e| {
                            VlsAdapterError::Protocol(format!(
                                "sign_counterparty_commitment:rgb_wire_tx:invalid_hex: {e}"
                            ))
                        })?;
                        let tx: bitcoin::Transaction =
                            consensus_deserialize_tx(&raw).map_err(|e| {
                                VlsAdapterError::Protocol(format!(
                                    "sign_counterparty_commitment:rgb_wire_tx:invalid_consensus_tx: {e}"
                                ))
                            })?;
                        let mut psbt = Psbt::from_unsigned_tx(tx.clone()).map_err(|e| {
                            VlsAdapterError::Protocol(format!(
                                "sign_counterparty_commitment:rgb_wire_tx:psbt_from_unsigned_tx: {e}"
                            ))
                        })?;

                        if let Some(wits) = commitment_psbt_output_witness_scripts_hex.as_ref() {
                            if wits.len() != psbt.outputs.len() {
                                return Err(VlsAdapterError::Protocol(format!(
                                    "sign_counterparty_commitment:rgb_wire_tx:witness_scripts_len {} != psbt.outputs.len {}",
                                    wits.len(),
                                    psbt.outputs.len()
                                )));
                            }
                            for (i, wh) in wits.iter().enumerate() {
                                let t = wh.trim();
                                if t.is_empty() {
                                    continue;
                                }
                                let bytes = hex::decode(t).map_err(|e| {
                                    VlsAdapterError::Protocol(format!(
                                        "sign_counterparty_commitment:rgb_wire_tx:witness_script_hex[{i}]: {e}"
                                    ))
                                })?;
                                psbt.outputs[i].witness_script = Some(ScriptBuf::from_bytes(bytes));
                            }
                        }

                        let reply: SignCommitmentTxWithHtlcsReply = call(
                            dbid,
                            PubKey(peer_id),
                            &*self.transport,
                            SignRemoteCommitmentTx {
                                tx: WithSize(tx),
                                psbt: WithSize(PsbtWrapper::from(psbt)),
                                remote_funding_key: PubKey(peer_id),
                                remote_per_commitment_point: PubKey(remote_per_commitment_point),
                                option_static_remotekey: true,
                                commitment_number,
                                htlcs: htlcs_tx2,
                                feerate: feerate_sat_per_kw,
                            },
                        )
                        .map_err(|e| {
                            VlsAdapterError::Transport(format!(
                                "sign_counterparty_commitment:rgb_wire_tx failed: {e:?}"
                            ))
                        })?;

                        return Ok(ChannelResponse::SignatureWithHtlcs {
                            signature_hex: hex::encode(reply.signature.signature.0),
                            htlc_signatures_hex: reply
                                .htlc_signatures
                                .iter()
                                .map(|s| hex::encode(s.signature.0))
                                .collect(),
                        });
                    } else {
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
                                htlcs: htlcs_tx2,
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
                }
                ChannelOp::SignClosingTransaction { tx_hex } => {
                    let raw = hex::decode(tx_hex.trim()).map_err(|e| {
                        VlsAdapterError::Protocol(format!(
                            "sign_closing_transaction:invalid_hex: {e}"
                        ))
                    })?;
                    let tx: bitcoin::Transaction = consensus_deserialize_tx(&raw).map_err(|e| {
                        VlsAdapterError::Protocol(format!(
                            "sign_closing_transaction:invalid_consensus_tx: {e}"
                        ))
                    })?;
                    let mut psbt = Psbt::from_unsigned_tx(tx.clone()).map_err(|e| {
                        VlsAdapterError::Protocol(format!(
                            "sign_closing_transaction:psbt_from_unsigned_tx: {e}"
                        ))
                    })?;
                    let holder_shutdown_script_hex = self.node_get_shutdown_scriptpubkey()?;
                    let holder_shutdown_script_bytes =
                        hex::decode(holder_shutdown_script_hex).map_err(|e| {
                            VlsAdapterError::Protocol(format!(
                                "sign_closing_transaction:invalid_shutdown_script_hex: {e}"
                            ))
                        })?;
                    let holder_shutdown_script =
                        ScriptBuf::from_bytes(holder_shutdown_script_bytes);
                    Self::attach_mutual_close_output_paths(
                        &mut psbt,
                        &holder_shutdown_script,
                    )?;

                    let reply: SignTxReply = call(
                        dbid,
                        PubKey(peer_id),
                        &*self.transport,
                        SignMutualCloseTx {
                            tx: WithSize(tx),
                            psbt: WithSize(PsbtWrapper::from(psbt)),
                            remote_funding_key: PubKey(peer_id),
                        },
                    )
                    .map_err(|e| {
                        VlsAdapterError::Transport(format!(
                            "sign_closing_transaction failed: {e:?}"
                        ))
                    })?;
                    Ok(ChannelResponse::Signature {
                        signature_hex: hex::encode(reply.signature.signature.0),
                    })
                }
                ChannelOp::SignJusticeRevokedOutput { .. }
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
            inputs: Vec<SpendableOutputSignInput>,
            psbt: String,
        ) -> Result<String, VlsAdapterError> {
            let witness_inputs = inputs.clone();
            let mut utxos: Vec<Utxo> = inputs
                .into_iter()
                .map(spendable_sign_input_to_vls_model)
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
            Self::populate_psbt_witness_utxos_from_sign_inputs(&mut psbt_obj, &witness_inputs)?;
            Self::normalize_psbt_input_key_origins(&mut psbt_obj);
            for (utxo, witness_input) in utxos.iter_mut().zip(witness_inputs.iter()) {
                if witness_input.script_pubkey_hex.is_empty() {
                    continue;
                }
                if matches!(
                    witness_input.descriptor_kind,
                    SpendableDescriptorKind::StaticOutput
                ) {
                    let script =
                        ScriptBuf::from_hex(&witness_input.script_pubkey_hex).map_err(|e| {
                            VlsAdapterError::Protocol(format!(
                                "invalid spendable input script_pubkey_hex for {}:{}: {e}",
                                witness_input.txid_hex, witness_input.vout
                            ))
                        })?;
                    if let Some(keyindex) = self.infer_keyindex_from_script(&script)? {
                        utxo.keyindex = keyindex;
                    }
                }
            }

            self.sign_withdrawal_with_utxos(utxos, psbt_obj)
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

        fn find_derivation_matches(
            &self,
            script_pubkey_hex: String,
            max_index: u32,
        ) -> Result<Vec<DerivedAddressMatch>, VlsAdapterError> {
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
                NodeRequest::EncryptPeerStoragePayload {
                    plaintext_hex,
                    random_bytes_hex,
                } => self
                    .client
                    .node_encrypt_peer_storage_payload(plaintext_hex, random_bytes_hex)
                    .map(|bytes_hex| {
                        SignerResponse::Node(NodeResponse::PeerStoragePayload { bytes_hex })
                    })
                    .map_err(Into::into),
                NodeRequest::DecryptPeerStoragePayload { ciphertext_hex } => self
                    .client
                    .node_decrypt_peer_storage_payload(ciphertext_hex)
                    .map(|bytes_hex| {
                        SignerResponse::Node(NodeResponse::DecryptedPeerStoragePayload { bytes_hex })
                    })
                    .map_err(Into::into),
                NodeRequest::EncryptBlindedMessagePayload {
                    plaintext_hex,
                    rho_hex,
                } => self
                    .client
                    .node_encrypt_blinded_message_payload(plaintext_hex, rho_hex)
                    .map(|bytes_hex| {
                        SignerResponse::Node(NodeResponse::BlindedMessagePayload { bytes_hex })
                    })
                    .map_err(Into::into),
                NodeRequest::DecryptBlindedMessagePayload {
                    ciphertext_hex,
                    rho_hex,
                } => self
                    .client
                    .node_decrypt_blinded_message_payload(ciphertext_hex, rho_hex)
                    .map(|(bytes_hex, used_aad)| {
                        SignerResponse::Node(NodeResponse::DecryptedBlindedMessagePayload {
                            bytes_hex,
                            used_aad,
                        })
                    })
                    .map_err(Into::into),
                NodeRequest::GetHmacForOfferKey => self
                    .client
                    .node_get_hmac_for_offer_key()
                    .map(|key_hex| SignerResponse::Node(NodeResponse::HmacForOfferKey { key_hex }))
                    .map_err(Into::into),
                NodeRequest::CryptForOffer { bytes_hex, nonce_hex } => self
                    .client
                    .node_crypt_for_offer(bytes_hex, nonce_hex)
                    .map(|bytes_hex| SignerResponse::Node(NodeResponse::CryptForOffer { bytes_hex }))
                    .map_err(Into::into),
                NodeRequest::CreateInboundPayment {
                    min_value_msat,
                    invoice_expiry_delta_secs,
                    random_bytes_hex,
                    current_time,
                    min_final_cltv_expiry_delta,
                } => self
                    .client
                    .node_create_inbound_payment(
                        min_value_msat,
                        invoice_expiry_delta_secs,
                        random_bytes_hex,
                        current_time,
                        min_final_cltv_expiry_delta,
                    )
                    .map(|(payment_hash_hex, payment_secret_hex)| {
                        SignerResponse::Node(NodeResponse::PaymentHashAndSecret {
                            payment_hash_hex,
                            payment_secret_hex,
                        })
                    })
                    .map_err(Into::into),
                NodeRequest::CreateInboundPaymentForHash {
                    payment_hash_hex,
                    min_value_msat,
                    invoice_expiry_delta_secs,
                    current_time,
                    min_final_cltv_expiry_delta,
                } => self
                    .client
                    .node_create_inbound_payment_for_hash(
                        payment_hash_hex,
                        min_value_msat,
                        invoice_expiry_delta_secs,
                        current_time,
                        min_final_cltv_expiry_delta,
                    )
                    .map(|payment_secret_hex| {
                        SignerResponse::Node(NodeResponse::PaymentSecret {
                            payment_secret_hex,
                        })
                    })
                    .map_err(Into::into),
                NodeRequest::CreateSpontaneousPaymentSecret {
                    min_value_msat,
                    invoice_expiry_delta_secs,
                    current_time,
                    min_final_cltv_expiry_delta,
                } => self
                    .client
                    .node_create_spontaneous_payment_secret(
                        min_value_msat,
                        invoice_expiry_delta_secs,
                        current_time,
                        min_final_cltv_expiry_delta,
                    )
                    .map(|payment_secret_hex| {
                        SignerResponse::Node(NodeResponse::PaymentSecret {
                            payment_secret_hex,
                        })
                    })
                    .map_err(Into::into),
                NodeRequest::VerifyInboundPayment {
                    payment_hash_hex,
                    payment_secret_hex,
                    total_msat,
                    highest_seen_timestamp,
                } => self
                    .client
                    .node_verify_inbound_payment(
                        payment_hash_hex,
                        payment_secret_hex,
                        total_msat,
                        highest_seen_timestamp,
                    )
                    .map(|(payment_preimage_hex, min_final_cltv_expiry_delta)| {
                        SignerResponse::Node(NodeResponse::VerifyInboundPayment {
                            payment_preimage_hex,
                            min_final_cltv_expiry_delta,
                        })
                    })
                    .map_err(Into::into),
                NodeRequest::GetPaymentPreimage {
                    payment_hash_hex,
                    payment_secret_hex,
                } => self
                    .client
                    .node_get_payment_preimage(payment_hash_hex, payment_secret_hex)
                    .map(|payment_preimage_hex| {
                        SignerResponse::Node(NodeResponse::PaymentPreimage {
                            payment_preimage_hex,
                        })
                    })
                    .map_err(Into::into),
                NodeRequest::PrepareAsyncPaymentsHashes {
                    host_node_id_hex,
                    start_index,
                    batch_size,
                } => self
                    .client
                    .node_prepare_async_payments_hashes(
                        host_node_id_hex,
                        start_index,
                        batch_size,
                    )
                    .map(|hashes| {
                        SignerResponse::Node(NodeResponse::AsyncPaymentsHashes { hashes })
                    })
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

            SignerRequest::SignSpendableOutputsPsbt { inputs, psbt } => self
                .client
                .sign_spendable_outputs_psbt(inputs, psbt)
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
            SignerRequest::FindDerivationMatches {
                script_pubkey_hex,
                max_index,
            } => self
                .client
                .find_derivation_matches(script_pubkey_hex, max_index)
                .map(|matches| SignerResponse::FindDerivationMatches { matches })
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
            Ok(BootstrapData {
                identity: SignerIdentity {
                    node_id: "n1".to_string(),
                    account_xpub_vanilla: "xv".to_string(),
                    account_xpub_colored: "xc".to_string(),
                    master_fingerprint: "ffff0000".to_string(),
                },
                protocol_version: "vls-test".to_string(),
                api_level: 1,
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

        fn node_encrypt_peer_storage_payload(
            &self,
            plaintext_hex: String,
            random_bytes_hex: String,
        ) -> Result<String, VlsAdapterError> {
            let (_, peer_storage_key, _) = derive_ldk_auxiliary_keys_hex_from_seed(&[9u8; 32])?;
            encrypt_peer_storage_payload_local(
                &peer_storage_key,
                plaintext_hex,
                random_bytes_hex,
            )
        }

        fn node_decrypt_peer_storage_payload(
            &self,
            ciphertext_hex: String,
        ) -> Result<String, VlsAdapterError> {
            let (_, peer_storage_key, _) = derive_ldk_auxiliary_keys_hex_from_seed(&[9u8; 32])?;
            decrypt_peer_storage_payload_local(&peer_storage_key, ciphertext_hex)
        }

        fn node_encrypt_blinded_message_payload(
            &self,
            plaintext_hex: String,
            rho_hex: String,
        ) -> Result<String, VlsAdapterError> {
            let (_, _, receive_auth_key) = derive_ldk_auxiliary_keys_hex_from_seed(&[9u8; 32])?;
            encrypt_blinded_message_payload_local(&receive_auth_key, plaintext_hex, rho_hex)
        }

        fn node_decrypt_blinded_message_payload(
            &self,
            ciphertext_hex: String,
            rho_hex: String,
        ) -> Result<(String, bool), VlsAdapterError> {
            let (_, _, receive_auth_key) = derive_ldk_auxiliary_keys_hex_from_seed(&[9u8; 32])?;
            decrypt_blinded_message_payload_local(&receive_auth_key, ciphertext_hex, rho_hex)
        }

        fn node_get_hmac_for_offer_key(&self) -> Result<String, VlsAdapterError> {
            let (inbound, _, _) = derive_ldk_auxiliary_keys_hex_from_seed(&[9u8; 32])?;
            let (offers_base_key, _) = offer_keys_from_inbound_key_hex(&inbound)?;
            Ok(hex::encode(offers_base_key))
        }

        fn node_crypt_for_offer(
            &self,
            bytes_hex: String,
            nonce_hex: String,
        ) -> Result<String, VlsAdapterError> {
            let (inbound, _, _) = derive_ldk_auxiliary_keys_hex_from_seed(&[9u8; 32])?;
            crypt_for_offer_local(&inbound, bytes_hex, nonce_hex)
        }

        fn node_create_inbound_payment(
            &self,
            _min_value_msat: Option<u64>,
            _invoice_expiry_delta_secs: u32,
            _random_bytes_hex: String,
            _current_time: u64,
            _min_final_cltv_expiry_delta: Option<u16>,
        ) -> Result<(String, String), VlsAdapterError> {
            Ok(("11".repeat(32), "22".repeat(32)))
        }

        fn node_create_inbound_payment_for_hash(
            &self,
            _payment_hash_hex: String,
            _min_value_msat: Option<u64>,
            _invoice_expiry_delta_secs: u32,
            _current_time: u64,
            _min_final_cltv_expiry_delta: Option<u16>,
        ) -> Result<String, VlsAdapterError> {
            Ok("22".repeat(32))
        }

        fn node_create_spontaneous_payment_secret(
            &self,
            _min_value_msat: Option<u64>,
            _invoice_expiry_delta_secs: u32,
            _current_time: u64,
            _min_final_cltv_expiry_delta: Option<u16>,
        ) -> Result<String, VlsAdapterError> {
            Ok("33".repeat(32))
        }

        fn node_verify_inbound_payment(
            &self,
            _payment_hash_hex: String,
            _payment_secret_hex: String,
            _total_msat: u64,
            _highest_seen_timestamp: u64,
        ) -> Result<(Option<String>, Option<u16>), VlsAdapterError> {
            Ok((Some("44".repeat(32)), Some(18)))
        }

        fn node_get_payment_preimage(
            &self,
            _payment_hash_hex: String,
            _payment_secret_hex: String,
        ) -> Result<String, VlsAdapterError> {
            Ok("55".repeat(32))
        }

        fn node_prepare_async_payments_hashes(
            &self,
            host_node_id_hex: String,
            start_index: u64,
            batch_size: u32,
        ) -> Result<Vec<AsyncPaymentsHashEntry>, VlsAdapterError> {
            derive_async_payments_hashes_from_seed(
                &[9u8; 32],
                bitcoin::Network::Regtest,
                &host_node_id_hex,
                start_index,
                batch_size,
            )
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
            inputs: Vec<SpendableOutputSignInput>,
            psbt: String,
        ) -> Result<String, VlsAdapterError> {
            Ok(format!("signed:{}:{psbt}", inputs.len()))
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

        fn find_derivation_matches(
            &self,
            _script_pubkey_hex: String,
            _max_index: u32,
        ) -> Result<Vec<DerivedAddressMatch>, VlsAdapterError> {
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
