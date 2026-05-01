#[cfg(test)]
mod tests {
    use signer_contract::{
        ChannelRequest, ChannelResponse, ExternalSignerBackend, NodeRequest, NodeResponse,
        SignerIdentity, SignerRequest, SignerResponse,
    };
    use signer_testkit::InMemorySigner;

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
}
