use signer_contract::{
    BootstrapData, ChannelPublicKeys, ChannelRequest, ChannelResponse, ExternalSignerBackend,
    NodeRequest, NodeResponse, SignerError, SignerIdentity, SignerRequest, SignerResponse,
};

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

impl ExternalSignerBackend for InMemorySigner {
    fn call(&self, req: SignerRequest) -> Result<SignerResponse, SignerError> {
        match req {
            SignerRequest::Bootstrap => Ok(SignerResponse::Bootstrap(BootstrapData {
                identity: self.identity.clone(),
                protocol_version: "v1-testkit".to_string(),
                api_level: 1,
            })),
            SignerRequest::Node(node_req) => match node_req {
                NodeRequest::GetNodeId { .. } => Ok(SignerResponse::Node(NodeResponse::NodeId {
                    node_id_hex: self.identity.node_id.clone(),
                })),
                NodeRequest::GetSecureRandomBytes => {
                    Ok(SignerResponse::Node(NodeResponse::RandomBytes {
                        bytes_hex: "00".repeat(32),
                    }))
                }
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
            SignerRequest::SignSpendableOutputsPsbt { descriptors, psbt } => {
                let marker = format!("signed:{}:{}", descriptors.len(), psbt);
                Ok(SignerResponse::SignedPsbt { psbt: marker })
            }
            SignerRequest::SignRgbPsbt { descriptors, psbt } => Ok(SignerResponse::SignedPsbt {
                psbt: format!("rgb-signed:{}:{psbt}", descriptors.len()),
            }),
            SignerRequest::GetWalletInputMetadata { .. } => {
                Ok(SignerResponse::WalletInputMetadata { metadata: None })
            }
            SignerRequest::DebugDeriveAddresses { .. } => {
                Ok(SignerResponse::DebugDeriveAddresses {
                    matches: Vec::new(),
                })
            }
        }
    }
}
