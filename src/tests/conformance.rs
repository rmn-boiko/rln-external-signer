#[cfg(test)]
mod tests {
    use crate::contract::{
        ChannelRequest, ChannelResponse, ExternalSignerBackend, NodeRequest, NodeResponse,
        SignerIdentity, SignerRequest, SignerResponse, SpendableDescriptorKind,
        SpendableOutputSignInput, WalletDerivationMatch,
    };
    use crate::test_utils::InMemorySigner;

    fn make_signer() -> InMemorySigner {
        InMemorySigner {
            identity: SignerIdentity {
                node_id: "node_id".to_string(),
                account_xpub_vanilla: "xpub_vanilla".to_string(),
                account_xpub_colored: "xpub_colored".to_string(),
                master_fingerprint: "f1f2f3f4".to_string(),
            },
        }
    }

    #[test]
    fn bootstrap_returns_identity() {
        let signer = make_signer();
        let res = signer.call(SignerRequest::Bootstrap).expect("bootstrap");
        match res {
            SignerResponse::Bootstrap(data) => assert_eq!(data.identity.node_id, "node_id"),
            _ => panic!("unexpected response"),
        }
    }

    #[test]
    fn node_sign_message_returns_signature() {
        let signer = make_signer();
        let res = signer
            .call(SignerRequest::Node(NodeRequest::SignMessage {
                message: "hello".to_string(),
            }))
            .expect("sign message");
        match res {
            SignerResponse::Node(NodeResponse::Signature { signature_hex }) => {
                assert_eq!(signature_hex, "sig:hello")
            }
            _ => panic!("unexpected response"),
        }
    }

    #[test]
    fn channel_generate_keys_id_returns_data() {
        let signer = make_signer();
        let res = signer
            .call(SignerRequest::Channel(
                ChannelRequest::GenerateChannelKeysId {
                    inbound: true,
                    channel_value_satoshis: 1000,
                    user_channel_id: 7,
                },
            ))
            .expect("generate keys id");
        match res {
            SignerResponse::Channel(ChannelResponse::GeneratedChannelKeysId {
                channel_keys_id_hex,
            }) => {
                assert!(channel_keys_id_hex.contains("keys:true:1000:7"));
            }
            _ => panic!("unexpected response"),
        }
    }

    #[test]
    fn rgb_psbt_signing_returns_marker() {
        let signer = make_signer();
        let res = signer
            .call(SignerRequest::SignRgbPsbt {
                descriptors: vec!["{}".to_string()],
                psbt: "psbt-data".to_string(),
            })
            .expect("rgb sign");
        match res {
            SignerResponse::SignedPsbt { psbt } => assert_eq!(psbt, "rgb-signed:1:psbt-data"),
            _ => panic!("unexpected response"),
        }
    }

    #[test]
    fn spendable_output_psbt_signing_returns_marker() {
        let signer = make_signer();
        let res = signer
            .call(SignerRequest::SignSpendableOutputsPsbt {
                inputs: vec![SpendableOutputSignInput {
                    descriptor_kind: SpendableDescriptorKind::StaticPaymentOutput,
                    txid_hex: "11".repeat(32),
                    vout: 1,
                    amount_sat: 42_000,
                    script_pubkey_hex: "0014".to_string(),
                    channel_keys_id_hex: Some("ab".repeat(32)),
                    wallet_derivation_match: Some(WalletDerivationMatch {
                        account_name: "vanilla".to_string(),
                        keyindex: 7,
                        derivation_path: "m/84'/1'/0'/0/7".to_string(),
                    }),
                    witness_script_hex: None,
                    redeem_script_hex: None,
                }],
                psbt: "psbt-data".to_string(),
            })
            .expect("spendable sign");
        match res {
            SignerResponse::SignedPsbt { psbt } => assert_eq!(psbt, "signed:1:psbt-data"),
            _ => panic!("unexpected response"),
        }
    }
}
