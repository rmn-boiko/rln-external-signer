use crate::contract::{
    AsyncPaymentsHashEntry, BootstrapData, ChannelPublicKeys, ChannelRequest, ChannelResponse,
    ExternalSignerBackend, NodeRequest, NodeResponse, SignerError, SignerIdentity,
    SignerRequest, SignerResponse,
};
use crate::ldk_keys_manager_material::derive_ldk_keys_manager_auxiliary_secret_bytes;

pub struct InMemorySigner {
    pub identity: SignerIdentity,
}

impl InMemorySigner {
    fn fake_sig(payload: &str) -> String {
        format!("sig:{payload}")
    }

    fn fixed_pubkeys() -> ChannelPublicKeys {
        ChannelPublicKeys {
            funding_pubkey_hex: "02f0".to_string(),
            revocation_basepoint_hex: "03f0".to_string(),
            payment_point_hex: "02f1".to_string(),
            delayed_payment_basepoint_hex: "03f1".to_string(),
            htlc_basepoint_hex: "02f2".to_string(),
        }
    }
}

fn testkit_ldk_aux_hexes() -> (String, String, String) {
    let seed = [1u8; 32];
    let (a, b, c) = derive_ldk_keys_manager_auxiliary_secret_bytes(&seed).expect("derive");
    (hex::encode(a), hex::encode(b), hex::encode(c))
}

impl ExternalSignerBackend for InMemorySigner {
    fn call(&self, req: SignerRequest) -> Result<SignerResponse, SignerError> {
        match req {
            SignerRequest::Bootstrap => {
                Ok(SignerResponse::Bootstrap(BootstrapData {
                    identity: self.identity.clone(),
                    protocol_version: "v1-testkit".to_string(),
                    api_level: 1,
                }))
            }
            SignerRequest::Node(node_req) => match node_req {
                NodeRequest::GetNodeId { .. } => Ok(SignerResponse::Node(NodeResponse::NodeId {
                    node_id_hex: self.identity.node_id.clone(),
                })),
                NodeRequest::GetSecureRandomBytes => {
                    Ok(SignerResponse::Node(NodeResponse::RandomBytes {
                        bytes_hex: "00".repeat(32),
                    }))
                }
                NodeRequest::EncryptPeerStoragePayload {
                    plaintext_hex,
                    random_bytes_hex,
                } => {
                    let (_, ldk_peer_storage_key_hex, _) = testkit_ldk_aux_hexes();
                    let bytes_hex = crate::vls_adapter::encrypt_peer_storage_payload_local(
                        &ldk_peer_storage_key_hex,
                        plaintext_hex,
                        random_bytes_hex,
                    )
                    .map_err(SignerError::from)?;
                    Ok(SignerResponse::Node(NodeResponse::PeerStoragePayload {
                        bytes_hex,
                    }))
                }
                NodeRequest::DecryptPeerStoragePayload { ciphertext_hex } => {
                    let (_, ldk_peer_storage_key_hex, _) = testkit_ldk_aux_hexes();
                    let bytes_hex = crate::vls_adapter::decrypt_peer_storage_payload_local(
                        &ldk_peer_storage_key_hex,
                        ciphertext_hex,
                    )
                    .map_err(SignerError::from)?;
                    Ok(SignerResponse::Node(
                        NodeResponse::DecryptedPeerStoragePayload { bytes_hex },
                    ))
                }
                NodeRequest::EncryptBlindedMessagePayload {
                    plaintext_hex,
                    rho_hex,
                } => {
                    let (_, _, ldk_receive_auth_key_hex) = testkit_ldk_aux_hexes();
                    let bytes_hex = crate::vls_adapter::encrypt_blinded_message_payload_local(
                        &ldk_receive_auth_key_hex,
                        plaintext_hex,
                        rho_hex,
                    )
                    .map_err(SignerError::from)?;
                    Ok(SignerResponse::Node(NodeResponse::BlindedMessagePayload {
                        bytes_hex,
                    }))
                }
                NodeRequest::DecryptBlindedMessagePayload {
                    ciphertext_hex,
                    rho_hex,
                } => {
                    let (_, _, ldk_receive_auth_key_hex) = testkit_ldk_aux_hexes();
                    let (bytes_hex, used_aad) =
                        crate::vls_adapter::decrypt_blinded_message_payload_local(
                            &ldk_receive_auth_key_hex,
                            ciphertext_hex,
                            rho_hex,
                        )
                        .map_err(SignerError::from)?;
                    Ok(SignerResponse::Node(
                        NodeResponse::DecryptedBlindedMessagePayload { bytes_hex, used_aad },
                    ))
                }
                NodeRequest::GetHmacForOfferKey => {
                    let (ldk_inbound_payment_key_hex, _, _) = testkit_ldk_aux_hexes();
                    let (offers_base_key, _) =
                        crate::vls_adapter::offer_keys_from_inbound_key_hex(&ldk_inbound_payment_key_hex)
                            .map_err(SignerError::from)?;
                    Ok(SignerResponse::Node(NodeResponse::HmacForOfferKey {
                        key_hex: hex::encode(offers_base_key),
                    }))
                }
                NodeRequest::CryptForOffer { bytes_hex, nonce_hex } => {
                    let (ldk_inbound_payment_key_hex, _, _) = testkit_ldk_aux_hexes();
                    let bytes_hex = crate::vls_adapter::crypt_for_offer_local(
                        &ldk_inbound_payment_key_hex,
                        bytes_hex,
                        nonce_hex,
                    )
                    .map_err(SignerError::from)?;
                    Ok(SignerResponse::Node(NodeResponse::CryptForOffer { bytes_hex }))
                }
                NodeRequest::PrepareAsyncPaymentsHashes {
                    start_index,
                    batch_size,
                    ..
                } => Ok(SignerResponse::Node(NodeResponse::AsyncPaymentsHashes {
                    hashes: (0..batch_size as u64)
                        .map(|offset| AsyncPaymentsHashEntry {
                            hash_index: start_index + offset,
                            payment_hash_hex: format!("{:064x}", start_index + offset),
                        })
                        .collect(),
                })),
                NodeRequest::CreateInboundPayment { .. } => Ok(SignerResponse::Node(
                    NodeResponse::PaymentHashAndSecret {
                        payment_hash_hex: "11".repeat(32),
                        payment_secret_hex: "22".repeat(32),
                    },
                )),
                NodeRequest::CreateInboundPaymentForHash { .. }
                | NodeRequest::CreateSpontaneousPaymentSecret { .. } => Ok(
                    SignerResponse::Node(NodeResponse::PaymentSecret {
                        payment_secret_hex: "22".repeat(32),
                    }),
                ),
                NodeRequest::VerifyInboundPayment { .. } => Ok(SignerResponse::Node(
                    NodeResponse::VerifyInboundPayment {
                        payment_preimage_hex: Some("33".repeat(32)),
                        min_final_cltv_expiry_delta: Some(18),
                    },
                )),
                NodeRequest::GetPaymentPreimage { .. } => Ok(SignerResponse::Node(
                    NodeResponse::PaymentPreimage {
                        payment_preimage_hex: "33".repeat(32),
                    },
                )),
                NodeRequest::GetDestinationScript { .. } | NodeRequest::GetShutdownScriptpubkey => {
                    Err(SignerError::Unsupported(
                        "destination/shutdown script ops are not implemented in testkit"
                            .to_string(),
                    ))
                }
                NodeRequest::SignMessage { message } => {
                    Ok(SignerResponse::Node(NodeResponse::Signature {
                        signature_hex: Self::fake_sig(&message),
                    }))
                }
                NodeRequest::SignGossipMessage { message_hex } => {
                    Ok(SignerResponse::Node(NodeResponse::Signature {
                        signature_hex: Self::fake_sig(&message_hex),
                    }))
                }
                NodeRequest::SignInvoice { hrp, u5bytes_hex } => {
                    Ok(SignerResponse::Node(NodeResponse::RecoverableSignature {
                        signature_hex: Self::fake_sig(&format!("{hrp}:{u5bytes_hex}")),
                        recovery_id: 1,
                    }))
                }
                NodeRequest::SignBolt12Invoice { invoice } => {
                    Ok(SignerResponse::Node(NodeResponse::Signature {
                        signature_hex: Self::fake_sig(&invoice),
                    }))
                }
                NodeRequest::Ecdh {
                    recipient,
                    other_key,
                    tweak,
                } => Ok(SignerResponse::Node(NodeResponse::Ecdh {
                    shared_secret_hex: format!(
                        "ss:{recipient}:{other_key}:{}",
                        tweak.unwrap_or_default()
                    ),
                })),
            },
            SignerRequest::Channel(channel_req) => match channel_req {
                ChannelRequest::GenerateChannelKeysId {
                    inbound,
                    channel_value_satoshis,
                    user_channel_id,
                } => Ok(SignerResponse::Channel(
                    ChannelResponse::GeneratedChannelKeysId {
                        channel_keys_id_hex: format!(
                            "keys:{inbound}:{channel_value_satoshis}:{user_channel_id}"
                        ),
                    },
                )),
                ChannelRequest::DeriveChannelSigner {
                    channel_value_satoshis,
                    channel_keys_id_hex,
                } => Ok(SignerResponse::Channel(
                    ChannelResponse::ChannelSignerData {
                        channel_signer_state_hex: format!(
                            "state:{channel_keys_id_hex}:{channel_value_satoshis}"
                        ),
                        channel_pubkeys: Self::fixed_pubkeys(),
                    },
                )),
                ChannelRequest::ReadChannelSigner {
                    channel_signer_state_hex,
                } => Ok(SignerResponse::Channel(
                    ChannelResponse::ChannelSignerData {
                        channel_signer_state_hex,
                        channel_pubkeys: Self::fixed_pubkeys(),
                    },
                )),
                ChannelRequest::Op {
                    channel_keys_id_hex,
                    op,
                } => {
                    let payload = format!("{channel_keys_id_hex}:{op:?}");
                    Ok(SignerResponse::Channel(ChannelResponse::Signature {
                        signature_hex: Self::fake_sig(&payload),
                    }))
                }
            },
            SignerRequest::SignSpendableOutputsPsbt { inputs, psbt } => {
                let marker = format!("signed:{}:{}", inputs.len(), psbt);
                Ok(SignerResponse::SignedPsbt { psbt: marker })
            }
            SignerRequest::SignRgbPsbt { descriptors, psbt } => Ok(SignerResponse::SignedPsbt {
                psbt: format!("rgb-signed:{}:{psbt}", descriptors.len()),
            }),
            SignerRequest::GetWalletInputMetadata { .. } => {
                Ok(SignerResponse::WalletInputMetadata { metadata: None })
            }
            SignerRequest::FindDerivationMatches { .. } => {
                Ok(SignerResponse::FindDerivationMatches {
                    matches: Vec::new(),
                })
            }
        }
    }
}
