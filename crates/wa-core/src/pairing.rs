use crate::{AuthCredentials, Browser, CoreError, CoreResult};
use base64::Engine;
use bytes::Bytes;
use prost::Message;
use wa_binary::{BinaryNode, BinaryNodeContent, JidServer, jid_encode};
use wa_crypto::{
    NoiseCertificateVerifier, SIGNAL_PUBLIC_KEY_VERSION, aes_256_ctr_apply,
    derive_pairing_code_key, sign_x25519, verify_hmac_sha256,
};
use wa_proto::proto::{
    AdvDeviceIdentity, AdvEncryptionType, AdvSignedDeviceIdentity, AdvSignedDeviceIdentityHmac,
};
use zeroize::Zeroize;

const LINKED_DEVICES_URL: &str = "https://wa.me/settings/linked_devices#";
const CROCKFORD_CHARACTERS: &[u8; 32] = b"123456789ABCDEFGHJKLMNPQRSTVWXYZ";
const ADV_ACCOUNT_SIGNATURE_PREFIX: [u8; 2] = [6, 0];
const ADV_DEVICE_SIGNATURE_PREFIX: [u8; 2] = [6, 1];
const ADV_HOSTED_ACCOUNT_SIGNATURE_PREFIX: [u8; 2] = [6, 5];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PairingCodeRequest {
    pub pairing_code: String,
    pub account_jid: String,
    pub node: BinaryNode,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PairDeviceChallenge {
    pub ack: BinaryNode,
    pub qr_codes: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PairSuccess {
    pub reply: BinaryNode,
    pub credentials: AuthCredentials,
    pub account_signature_key: Bytes,
    pub signed_device_identity: Bytes,
    pub key_index: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PairingKeyMaterial {
    pub salt: [u8; 32],
    pub iv: [u8; 16],
}

impl PairingKeyMaterial {
    #[must_use]
    pub fn random() -> Self {
        Self {
            salt: rand::random(),
            iv: rand::random(),
        }
    }
}

#[must_use]
pub fn build_pairing_qr_data(
    reference: &str,
    credentials: &AuthCredentials,
    browser: &Browser,
) -> String {
    let engine = base64::engine::general_purpose::STANDARD;
    let noise_key = engine.encode(credentials.noise_key.public);
    let identity_key = engine.encode(credentials.signed_identity_key.public);
    let adv_secret = engine.encode(credentials.adv_secret_key.expose());

    format!(
        "{}{},{},{},{},{}",
        LINKED_DEVICES_URL,
        reference,
        noise_key,
        identity_key,
        adv_secret,
        companion_platform_id(browser)
    )
}

pub fn build_pairing_code_request(
    credentials: &AuthCredentials,
    browser: &Browser,
    phone_number: &str,
    custom_pairing_code: Option<&str>,
    tag: impl Into<String>,
) -> CoreResult<PairingCodeRequest> {
    let random_code_bytes: [u8; 5] = rand::random();
    build_pairing_code_request_with_material(
        credentials,
        browser,
        phone_number,
        custom_pairing_code,
        tag,
        PairingKeyMaterial::random(),
        &random_code_bytes,
    )
}

pub fn build_pairing_code_request_with_material(
    credentials: &AuthCredentials,
    browser: &Browser,
    phone_number: &str,
    custom_pairing_code: Option<&str>,
    tag: impl Into<String>,
    material: PairingKeyMaterial,
    random_code_bytes: &[u8; 5],
) -> CoreResult<PairingCodeRequest> {
    let pairing_code = match custom_pairing_code {
        Some(value) => validate_custom_pairing_code(value)?.to_owned(),
        None => bytes_to_crockford(random_code_bytes),
    };
    let account_jid = phone_number_jid(phone_number)?;
    let wrapped_key = wrap_pairing_ephemeral_public_key(credentials, &pairing_code, material)?;
    let platform_id = companion_platform_id(browser).to_string();
    let platform_display = companion_platform_display(browser);

    let node = BinaryNode::new("iq")
        .with_attr("to", "s.whatsapp.net")
        .with_attr("type", "set")
        .with_attr("id", tag)
        .with_attr("xmlns", "md")
        .with_content(vec![
            BinaryNode::new("link_code_companion_reg")
                .with_attr("jid", account_jid.clone())
                .with_attr("stage", "companion_hello")
                .with_attr("should_show_push_notification", "true")
                .with_content(vec![
                    BinaryNode::new("link_code_pairing_wrapped_companion_ephemeral_pub")
                        .with_content(wrapped_key),
                    BinaryNode::new("companion_server_auth_key_pub")
                        .with_content(Bytes::copy_from_slice(&credentials.noise_key.public)),
                    BinaryNode::new("companion_platform_id").with_content(platform_id),
                    BinaryNode::new("companion_platform_display").with_content(platform_display),
                    BinaryNode::new("link_code_pairing_nonce").with_content("0"),
                ]),
        ]);

    Ok(PairingCodeRequest {
        pairing_code,
        account_jid,
        node,
    })
}

pub fn handle_pair_device_challenge(
    stanza: &BinaryNode,
    credentials: &AuthCredentials,
    browser: &Browser,
) -> CoreResult<PairDeviceChallenge> {
    let id = stanza
        .attrs
        .get("id")
        .ok_or_else(|| CoreError::Protocol("pair-device stanza missing id".to_owned()))?;
    let pair_device = child_node(stanza, "pair-device")
        .ok_or_else(|| CoreError::Protocol("missing pair-device node".to_owned()))?;
    let refs = child_nodes(pair_device, "ref");
    if refs.is_empty() {
        return Err(CoreError::Protocol(
            "pair-device stanza contains no refs".to_owned(),
        ));
    }

    let mut qr_codes = Vec::with_capacity(refs.len());
    for reference in refs {
        qr_codes.push(build_pairing_qr_data(
            &node_text(reference)?,
            credentials,
            browser,
        ));
    }

    Ok(PairDeviceChallenge {
        ack: BinaryNode::new("iq")
            .with_attr("to", "s.whatsapp.net")
            .with_attr("type", "result")
            .with_attr("id", id.clone()),
        qr_codes,
    })
}

pub fn handle_pair_success<V>(
    stanza: &BinaryNode,
    credentials: &AuthCredentials,
    verifier: &V,
) -> CoreResult<PairSuccess>
where
    V: NoiseCertificateVerifier,
{
    let id = stanza
        .attrs
        .get("id")
        .ok_or_else(|| CoreError::Protocol("pair-success stanza missing id".to_owned()))?;
    let pair_success = child_node(stanza, "pair-success")
        .ok_or_else(|| CoreError::Protocol("missing pair-success node".to_owned()))?;
    let device_identity_node = child_node(pair_success, "device-identity")
        .ok_or_else(|| CoreError::Protocol("missing device-identity node".to_owned()))?;
    let device_node = child_node(pair_success, "device")
        .ok_or_else(|| CoreError::Protocol("missing device node".to_owned()))?;

    let identity_hmac = AdvSignedDeviceIdentityHmac::decode(node_bytes(device_identity_node)?)?;
    let identity_details = identity_hmac
        .details
        .ok_or_else(|| CoreError::Protocol("missing signed identity details".to_owned()))?;
    let expected_hmac = identity_hmac
        .hmac
        .ok_or_else(|| CoreError::Protocol("missing signed identity hmac".to_owned()))?;
    let hmac_prefix = if identity_hmac.account_type == Some(AdvEncryptionType::Hosted as i32) {
        ADV_HOSTED_ACCOUNT_SIGNATURE_PREFIX.as_slice()
    } else {
        &[]
    };
    let mut hmac_message = Vec::with_capacity(hmac_prefix.len() + identity_details.len());
    hmac_message.extend_from_slice(hmac_prefix);
    hmac_message.extend_from_slice(&identity_details);
    if !verify_hmac_sha256(
        &hmac_message,
        credentials.adv_secret_key.expose(),
        &expected_hmac,
    )? {
        return Err(CoreError::Protocol(
            "invalid signed identity hmac".to_owned(),
        ));
    }

    let mut account = AdvSignedDeviceIdentity::decode(identity_details.clone())?;
    let account_signature_key = account
        .account_signature_key
        .clone()
        .ok_or_else(|| CoreError::Protocol("missing account signature key".to_owned()))?;
    let account_signature = account
        .account_signature
        .clone()
        .ok_or_else(|| CoreError::Protocol("missing account signature".to_owned()))?;
    let device_details = account
        .details
        .clone()
        .ok_or_else(|| CoreError::Protocol("missing device details".to_owned()))?;
    let device_identity = AdvDeviceIdentity::decode(device_details.clone())?;
    let key_index = device_identity
        .key_index
        .ok_or_else(|| CoreError::Protocol("missing device identity key index".to_owned()))?;

    let account_signature_prefix =
        if device_identity.device_type == Some(AdvEncryptionType::Hosted as i32) {
            ADV_HOSTED_ACCOUNT_SIGNATURE_PREFIX.as_slice()
        } else {
            ADV_ACCOUNT_SIGNATURE_PREFIX.as_slice()
        };
    let mut account_message = Vec::with_capacity(
        account_signature_prefix.len()
            + device_details.len()
            + credentials.signed_identity_key.public.len(),
    );
    account_message.extend_from_slice(account_signature_prefix);
    account_message.extend_from_slice(&device_details);
    account_message.extend_from_slice(&credentials.signed_identity_key.public);

    let account_signature_public = x25519_public_key(&account_signature_key)?;
    if !verifier.verify_signature(
        &account_signature_public,
        &account_message,
        &account_signature,
    ) {
        return Err(CoreError::Protocol("invalid account signature".to_owned()));
    }

    let mut device_message = Vec::with_capacity(
        ADV_DEVICE_SIGNATURE_PREFIX.len()
            + device_details.len()
            + credentials.signed_identity_key.public.len()
            + account_signature_key.len(),
    );
    device_message.extend_from_slice(&ADV_DEVICE_SIGNATURE_PREFIX);
    device_message.extend_from_slice(&device_details);
    device_message.extend_from_slice(&credentials.signed_identity_key.public);
    device_message.extend_from_slice(&account_signature_key);
    let device_signature = sign_x25519(
        credentials.signed_identity_key.private.expose(),
        &device_message,
    )?;

    account.device_signature = Some(Bytes::copy_from_slice(&device_signature));
    account.account_signature_key = None;
    let signed_device_identity = Bytes::from(account.encode_to_vec());

    let reply = BinaryNode::new("iq")
        .with_attr("to", "s.whatsapp.net")
        .with_attr("type", "result")
        .with_attr("id", id.clone())
        .with_content(vec![BinaryNode::new("pair-device-sign").with_content(
            vec![
                BinaryNode::new("device-identity")
                    .with_attr("key-index", key_index.to_string())
                    .with_content(signed_device_identity.clone()),
            ],
        )]);

    let mut updated = credentials.clone();
    updated.registered = true;
    updated.account_jid = device_node.attrs.get("jid").cloned();
    updated.account_lid = device_node.attrs.get("lid").cloned();
    updated.account_name =
        child_node(pair_success, "biz").and_then(|node| node.attrs.get("name").cloned());
    updated.account_platform =
        child_node(pair_success, "platform").and_then(|node| node.attrs.get("name").cloned());
    updated.account_signature_key = Some(account_signature_key.clone());
    updated.signed_device_identity = Some(signed_device_identity.clone());
    updated.pairing_code = None;

    Ok(PairSuccess {
        reply,
        credentials: updated,
        account_signature_key,
        signed_device_identity,
        key_index,
    })
}

pub fn wrap_pairing_ephemeral_public_key(
    credentials: &AuthCredentials,
    pairing_code: &str,
    material: PairingKeyMaterial,
) -> CoreResult<Bytes> {
    let mut key = derive_pairing_code_key(pairing_code, &material.salt);
    let encrypted = aes_256_ctr_apply(
        &credentials.pairing_ephemeral_key_pair.public,
        &key,
        &material.iv,
    )?;
    key.zeroize();

    let mut out = Vec::with_capacity(material.salt.len() + material.iv.len() + encrypted.len());
    out.extend_from_slice(&material.salt);
    out.extend_from_slice(&material.iv);
    out.extend_from_slice(&encrypted);
    Ok(Bytes::from(out))
}

#[must_use]
pub fn bytes_to_crockford(input: &[u8]) -> String {
    let mut value = 0u32;
    let mut bit_count = 0u8;
    let mut out = String::with_capacity(input.len().div_ceil(5) * 8);

    for byte in input {
        value = (value << 8) | u32::from(*byte);
        bit_count += 8;

        while bit_count >= 5 {
            let index = ((value >> (bit_count - 5)) & 31) as usize;
            out.push(CROCKFORD_CHARACTERS[index] as char);
            bit_count -= 5;
        }
    }

    if bit_count > 0 {
        let index = ((value << (5 - bit_count)) & 31) as usize;
        out.push(CROCKFORD_CHARACTERS[index] as char);
    }

    out
}

#[must_use]
pub fn companion_platform_id(browser: &Browser) -> u8 {
    match browser.name.as_str() {
        "Desktop" if browser.os == "Windows" => 8,
        "Desktop" => 7,
        "Chrome" => 1,
        "Edge" => 2,
        "Firefox" => 3,
        "IE" => 4,
        "Opera" => 5,
        "Safari" => 6,
        _ => 9,
    }
}

#[must_use]
pub fn companion_platform_display(browser: &Browser) -> String {
    format!("{} ({})", browser.name, browser.os)
}

fn validate_custom_pairing_code(pairing_code: &str) -> CoreResult<&str> {
    if pairing_code.len() != 8 {
        return Err(CoreError::Payload(
            "custom pairing code must be exactly 8 characters".to_owned(),
        ));
    }
    Ok(pairing_code)
}

fn phone_number_jid(phone_number: &str) -> CoreResult<String> {
    let phone_number = phone_number.trim().trim_start_matches('+');
    let mut normalized = String::with_capacity(phone_number.len());
    for ch in phone_number.chars() {
        if ch.is_ascii_digit() {
            normalized.push(ch);
        } else if ch == ' ' || ch == '-' {
            continue;
        } else {
            return Err(CoreError::Payload(format!(
                "invalid phone number character: {ch}"
            )));
        }
    }

    if normalized.is_empty() {
        return Err(CoreError::Payload("phone number is empty".to_owned()));
    }

    Ok(jid_encode(normalized, JidServer::SWhatsAppNet, None, None))
}

fn child_node<'a>(node: &'a BinaryNode, tag: &str) -> Option<&'a BinaryNode> {
    child_nodes(node, tag).into_iter().next()
}

fn child_nodes<'a>(node: &'a BinaryNode, tag: &str) -> Vec<&'a BinaryNode> {
    let Some(BinaryNodeContent::Nodes(children)) = &node.content else {
        return Vec::new();
    };

    children.iter().filter(|child| child.tag == tag).collect()
}

fn node_text(node: &BinaryNode) -> CoreResult<String> {
    match &node.content {
        Some(BinaryNodeContent::Text(value)) => Ok(value.clone()),
        Some(BinaryNodeContent::Bytes(value)) => String::from_utf8(value.to_vec())
            .map_err(|err| CoreError::Protocol(format!("invalid ref text: {err}"))),
        _ => Err(CoreError::Protocol("ref node has no text".to_owned())),
    }
}

fn node_bytes(node: &BinaryNode) -> CoreResult<Bytes> {
    match &node.content {
        Some(BinaryNodeContent::Bytes(value)) => Ok(value.clone()),
        Some(BinaryNodeContent::Text(value)) => Ok(Bytes::copy_from_slice(value.as_bytes())),
        _ => Err(CoreError::Protocol("node has no bytes".to_owned())),
    }
}

fn x25519_public_key(public_key: &[u8]) -> CoreResult<[u8; 32]> {
    if public_key.len() == 33 && public_key[0] == SIGNAL_PUBLIC_KEY_VERSION {
        public_key[1..]
            .try_into()
            .map_err(|_| CoreError::Protocol("invalid account signature key".to_owned()))
    } else {
        public_key
            .try_into()
            .map_err(|_| CoreError::Protocol("invalid account signature key".to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::create_initial_credentials;
    use base64::Engine;
    use wa_crypto::{
        NoiseCertificateVerifier, XEdDsaNoiseCertificateVerifier, aes_256_ctr_apply,
        derive_pairing_code_key, generate_key_pair, hmac_sha256,
    };

    #[test]
    fn builds_linked_device_qr_data() {
        let credentials = create_initial_credentials().unwrap();
        let browser = Browser::macos_chrome();
        let qr = build_pairing_qr_data("ref-1", &credentials, &browser);
        let engine = base64::engine::general_purpose::STANDARD;

        assert_eq!(
            qr,
            format!(
                "{}ref-1,{},{},{},1",
                LINKED_DEVICES_URL,
                engine.encode(credentials.noise_key.public),
                engine.encode(credentials.signed_identity_key.public),
                engine.encode(credentials.adv_secret_key.expose())
            )
        );
    }

    #[test]
    fn builds_pairing_code_request_node() {
        let credentials = create_initial_credentials().unwrap();
        let material = PairingKeyMaterial {
            salt: [1u8; 32],
            iv: [2u8; 16],
        };
        let request = build_pairing_code_request_with_material(
            &credentials,
            &Browser::macos_chrome(),
            "+1 234-567",
            Some("ABCDEFGH"),
            "tag-1",
            material,
            &[0u8; 5],
        )
        .unwrap();

        assert_eq!(request.pairing_code, "ABCDEFGH");
        assert_eq!(request.account_jid, "1234567@s.whatsapp.net");
        assert_eq!(request.node.tag, "iq");
        assert_eq!(request.node.attrs["id"], "tag-1");

        let registration = only_child(&request.node, "link_code_companion_reg");
        assert_eq!(registration.attrs["jid"], "1234567@s.whatsapp.net");
        assert_eq!(registration.attrs["stage"], "companion_hello");

        let wrapped = only_child(
            registration,
            "link_code_pairing_wrapped_companion_ephemeral_pub",
        );
        let wrapped = bytes_content(wrapped);
        assert_eq!(&wrapped[..32], &[1u8; 32]);
        assert_eq!(&wrapped[32..48], &[2u8; 16]);
        let key = derive_pairing_code_key("ABCDEFGH", &material.salt);
        let decrypted = aes_256_ctr_apply(&wrapped[48..], &key, &material.iv).unwrap();
        assert_eq!(decrypted, credentials.pairing_ephemeral_key_pair.public);

        assert_eq!(
            text_content(only_child(registration, "companion_platform_id")),
            "1"
        );
        assert_eq!(
            text_content(only_child(registration, "companion_platform_display")),
            "Chrome (Mac OS)"
        );
        assert_eq!(
            bytes_content(only_child(registration, "companion_server_auth_key_pub")),
            Bytes::copy_from_slice(&credentials.noise_key.public)
        );
    }

    #[test]
    fn generated_pairing_code_uses_crockford_alphabet() {
        assert_eq!(bytes_to_crockford(&[0, 0, 0, 0, 0]), "11111111");
        assert_eq!(
            bytes_to_crockford(&[0xff, 0xff, 0xff, 0xff, 0xff]),
            "ZZZZZZZZ"
        );
    }

    #[test]
    fn rejects_invalid_pairing_request_inputs() {
        let credentials = create_initial_credentials().unwrap();
        let material = PairingKeyMaterial {
            salt: [1u8; 32],
            iv: [2u8; 16],
        };

        assert!(
            build_pairing_code_request_with_material(
                &credentials,
                &Browser::macos_chrome(),
                "12345",
                Some("short"),
                "tag",
                material,
                &[0u8; 5],
            )
            .is_err()
        );
        assert!(
            build_pairing_code_request_with_material(
                &credentials,
                &Browser::macos_chrome(),
                "12x45",
                Some("ABCDEFGH"),
                "tag",
                material,
                &[0u8; 5],
            )
            .is_err()
        );
    }

    #[test]
    fn handles_pair_device_challenge() {
        let credentials = create_initial_credentials().unwrap();
        let stanza = BinaryNode::new("iq")
            .with_attr("id", "pair-1")
            .with_attr("type", "set")
            .with_content(vec![BinaryNode::new("pair-device").with_content(vec![
                BinaryNode::new("ref").with_content("ref-a"),
                BinaryNode::new("ref").with_content(Bytes::from_static(b"ref-b")),
            ])]);

        let challenge =
            handle_pair_device_challenge(&stanza, &credentials, &Browser::macos_chrome()).unwrap();

        assert_eq!(
            challenge.ack,
            BinaryNode::new("iq")
                .with_attr("to", "s.whatsapp.net")
                .with_attr("type", "result")
                .with_attr("id", "pair-1")
        );
        assert_eq!(challenge.qr_codes.len(), 2);
        assert!(challenge.qr_codes[0].contains("#ref-a,"));
        assert!(challenge.qr_codes[1].contains("#ref-b,"));
    }

    #[test]
    fn rejects_pair_device_challenge_without_refs() {
        let credentials = create_initial_credentials().unwrap();
        let stanza = BinaryNode::new("iq")
            .with_attr("id", "pair-1")
            .with_content(vec![BinaryNode::new("pair-device")]);

        assert!(
            handle_pair_device_challenge(&stanza, &credentials, &Browser::macos_chrome()).is_err()
        );
    }

    #[test]
    fn handles_pair_success_and_builds_device_sign_reply() {
        let credentials = create_initial_credentials().unwrap();
        let account_key = generate_key_pair();
        let stanza = pair_success_stanza(&credentials, &account_key, false, false);

        let success =
            handle_pair_success(&stanza, &credentials, &XEdDsaNoiseCertificateVerifier).unwrap();

        assert_eq!(
            success.credentials.account_jid.as_deref(),
            Some("12345:7@s.whatsapp.net")
        );
        assert_eq!(success.credentials.account_lid.as_deref(), Some("abc@lid"));
        assert_eq!(success.credentials.account_name.as_deref(), Some("Biz"));
        assert_eq!(
            success.credentials.account_platform.as_deref(),
            Some("Chrome")
        );
        assert!(success.credentials.registered);
        assert_eq!(
            success.credentials.account_signature_key,
            Some(Bytes::copy_from_slice(&account_key.public))
        );
        assert_eq!(
            success.credentials.signed_device_identity.as_ref(),
            Some(&success.signed_device_identity)
        );
        assert_eq!(success.key_index, 9);

        let sign = only_child(&success.reply, "pair-device-sign");
        let device_identity = only_child(sign, "device-identity");
        assert_eq!(device_identity.attrs["key-index"], "9");
        assert_eq!(
            bytes_content(device_identity),
            &success.signed_device_identity
        );
        let signed =
            AdvSignedDeviceIdentity::decode(success.signed_device_identity.clone()).unwrap();
        assert!(signed.account_signature_key.is_none());
        assert!(signed.device_signature.is_some());

        let details = signed.details.unwrap();
        let mut device_message = Vec::new();
        device_message.extend_from_slice(&ADV_DEVICE_SIGNATURE_PREFIX);
        device_message.extend_from_slice(&details);
        device_message.extend_from_slice(&credentials.signed_identity_key.public);
        device_message.extend_from_slice(&account_key.public);
        assert!(XEdDsaNoiseCertificateVerifier.verify_signature(
            &credentials.signed_identity_key.public,
            &device_message,
            &signed.device_signature.unwrap()
        ));
    }

    #[test]
    fn rejects_pair_success_with_invalid_hmac() {
        let credentials = create_initial_credentials().unwrap();
        let account_key = generate_key_pair();
        let stanza = pair_success_stanza(&credentials, &account_key, true, false);

        assert!(
            handle_pair_success(&stanza, &credentials, &XEdDsaNoiseCertificateVerifier).is_err()
        );
    }

    #[test]
    fn rejects_pair_success_with_invalid_account_signature() {
        let credentials = create_initial_credentials().unwrap();
        let account_key = generate_key_pair();
        let stanza = pair_success_stanza(&credentials, &account_key, false, true);

        assert!(
            handle_pair_success(&stanza, &credentials, &XEdDsaNoiseCertificateVerifier).is_err()
        );
    }

    fn only_child<'a>(node: &'a BinaryNode, tag: &str) -> &'a BinaryNode {
        let Some(BinaryNodeContent::Nodes(children)) = &node.content else {
            panic!("missing node children");
        };
        children
            .iter()
            .find(|child| child.tag == tag)
            .expect("missing child")
    }

    fn bytes_content(node: &BinaryNode) -> Bytes {
        match &node.content {
            Some(BinaryNodeContent::Bytes(value)) => value.clone(),
            _ => panic!("missing bytes"),
        }
    }

    fn text_content(node: &BinaryNode) -> &str {
        match &node.content {
            Some(BinaryNodeContent::Text(value)) => value,
            _ => panic!("missing text"),
        }
    }

    fn pair_success_stanza(
        credentials: &AuthCredentials,
        account_key: &wa_crypto::KeyPair,
        corrupt_hmac: bool,
        corrupt_signature: bool,
    ) -> BinaryNode {
        let device_details = AdvDeviceIdentity {
            raw_id: Some(1),
            timestamp: Some(2),
            key_index: Some(9),
            account_type: Some(AdvEncryptionType::E2ee as i32),
            device_type: Some(AdvEncryptionType::E2ee as i32),
        }
        .encode_to_vec();

        let mut account_message = Vec::new();
        account_message.extend_from_slice(&ADV_ACCOUNT_SIGNATURE_PREFIX);
        account_message.extend_from_slice(&device_details);
        account_message.extend_from_slice(&credentials.signed_identity_key.public);
        let mut account_signature =
            wa_crypto::sign_x25519(account_key.private.expose(), &account_message).unwrap();
        if corrupt_signature {
            account_signature[0] ^= 1;
        }

        let account = AdvSignedDeviceIdentity {
            details: Some(Bytes::from(device_details)),
            account_signature_key: Some(Bytes::copy_from_slice(&account_key.public)),
            account_signature: Some(Bytes::copy_from_slice(&account_signature)),
            device_signature: None,
        };
        let account_details = account.encode_to_vec();
        let mut hmac = hmac_sha256(&account_details, credentials.adv_secret_key.expose()).unwrap();
        if corrupt_hmac {
            hmac[0] ^= 1;
        }
        let wrapped = AdvSignedDeviceIdentityHmac {
            details: Some(Bytes::from(account_details)),
            hmac: Some(Bytes::copy_from_slice(&hmac)),
            account_type: Some(AdvEncryptionType::E2ee as i32),
        }
        .encode_to_vec();

        BinaryNode::new("iq")
            .with_attr("id", "success-1")
            .with_content(vec![BinaryNode::new("pair-success").with_content(vec![
                BinaryNode::new("device-identity").with_content(Bytes::from(wrapped)),
                BinaryNode::new("platform").with_attr("name", "Chrome"),
                BinaryNode::new("device")
                    .with_attr("jid", "12345:7@s.whatsapp.net")
                    .with_attr("lid", "abc@lid"),
                BinaryNode::new("biz").with_attr("name", "Biz"),
            ])])
    }
}
