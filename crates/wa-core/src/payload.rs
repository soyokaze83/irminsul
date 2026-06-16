use crate::{Browser, ClientConfig, CoreError, CoreResult, WaVersion};
use bytes::Bytes;
use md5::{Digest, Md5};
use prost::Message;
use wa_binary::jid_decode;
use wa_proto::proto::client_payload::user_agent;
use wa_proto::proto::client_payload::web_info::WebSubPlatform;
use wa_proto::proto::client_payload::{
    ConnectReason, ConnectType, DevicePairingRegistrationData, UserAgent, WebInfo,
};
use wa_proto::proto::device_props::{self, HistorySyncConfig, PlatformType};
use wa_proto::proto::{ClientPayload, DeviceProps};

pub const KEY_BUNDLE_TYPE: [u8; 1] = [5];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegistrationPayloadKeys {
    pub registration_id: u32,
    pub signed_identity_public: Bytes,
    pub signed_pre_key_id: u32,
    pub signed_pre_key_public: Bytes,
    pub signed_pre_key_signature: Bytes,
}

pub fn build_login_payload(user_jid: &str, config: &ClientConfig) -> CoreResult<ClientPayload> {
    let jid = jid_decode(user_jid).ok_or_else(|| {
        CoreError::Payload(format!("invalid user jid for login payload: {user_jid}"))
    })?;
    let username = jid.user.parse::<u64>().map_err(|_| {
        CoreError::Payload(format!(
            "invalid numeric user id for login payload: {}",
            jid.user
        ))
    })?;

    let mut payload = base_client_payload(config);
    payload.passive = Some(true);
    payload.pull = Some(true);
    payload.username = Some(username);
    payload.device = jid.device.map(u32::from);
    payload.lid_db_migrated = Some(false);
    Ok(payload)
}

pub fn build_registration_payload(
    keys: RegistrationPayloadKeys,
    config: &ClientConfig,
) -> CoreResult<ClientPayload> {
    let mut payload = base_client_payload(config);
    payload.passive = Some(false);
    payload.pull = Some(false);
    payload.device_pairing_data = Some(DevicePairingRegistrationData {
        e_regid: Some(encode_big_endian(keys.registration_id, 4)?),
        e_keytype: Some(Bytes::copy_from_slice(&KEY_BUNDLE_TYPE)),
        e_ident: Some(keys.signed_identity_public),
        e_skey_id: Some(encode_big_endian(keys.signed_pre_key_id, 3)?),
        e_skey_val: Some(keys.signed_pre_key_public),
        e_skey_sig: Some(keys.signed_pre_key_signature),
        build_hash: Some(version_hash(config.version)),
        device_props: Some(build_device_props(config).encode_to_vec().into()),
    });
    Ok(payload)
}

#[must_use]
pub fn base_client_payload(config: &ClientConfig) -> ClientPayload {
    ClientPayload {
        connect_type: Some(ConnectType::WifiUnknown as i32),
        connect_reason: Some(ConnectReason::UserActivated as i32),
        user_agent: Some(user_agent(config)),
        web_info: Some(web_info(config)),
        push_name: config.push_name.clone(),
        ..ClientPayload::default()
    }
}

#[must_use]
pub fn user_agent(config: &ClientConfig) -> UserAgent {
    UserAgent {
        platform: Some(user_agent::Platform::Web as i32),
        app_version: Some(user_agent::AppVersion {
            primary: Some(config.version.0),
            secondary: Some(config.version.1),
            tertiary: Some(config.version.2),
            quaternary: None,
            quinary: None,
        }),
        mcc: Some("000".to_owned()),
        mnc: Some("000".to_owned()),
        os_version: Some("0.1".to_owned()),
        manufacturer: None,
        device: Some("Desktop".to_owned()),
        os_build_number: Some("0.1".to_owned()),
        phone_id: None,
        release_channel: Some(user_agent::ReleaseChannel::Release as i32),
        locale_language_iso6391: Some("en".to_owned()),
        locale_country_iso31661_alpha2: Some(config.country_code.clone()),
        device_board: None,
        device_exp_id: None,
        device_type: None,
        device_model_type: None,
    }
}

#[must_use]
pub fn web_info(config: &ClientConfig) -> WebInfo {
    WebInfo {
        ref_token: None,
        version: None,
        webd_payload: None,
        web_sub_platform: Some(web_sub_platform(&config.browser, config.sync_full_history) as i32),
    }
}

#[must_use]
pub fn build_device_props(config: &ClientConfig) -> DeviceProps {
    DeviceProps {
        os: Some(config.browser.os.clone()),
        version: Some(device_props::AppVersion {
            primary: Some(10),
            secondary: Some(15),
            tertiary: Some(7),
            quaternary: None,
            quinary: None,
        }),
        platform_type: Some(platform_type(&config.browser.name) as i32),
        require_full_sync: Some(config.sync_full_history),
        history_sync_config: Some(HistorySyncConfig {
            full_sync_days_limit: None,
            full_sync_size_mb_limit: None,
            storage_quota_mb: Some(10240),
            inline_initial_payload_in_e2_ee_msg: Some(true),
            recent_sync_days_limit: None,
            support_call_log_history: Some(false),
            support_bot_user_agent_chat_history: Some(true),
            support_cag_reactions_and_polls: Some(true),
            support_biz_hosted_msg: Some(true),
            support_recent_sync_chunk_message_count_tuning: Some(true),
            support_hosted_group_msg: Some(true),
            support_fbid_bot_chat_history: Some(true),
            support_add_on_history_sync_migration: None,
            support_message_association: Some(true),
            support_group_history: Some(false),
            on_demand_ready: None,
            support_guest_chat: None,
            complete_on_demand_ready: None,
            thumbnail_sync_days_limit: None,
        }),
    }
}

#[must_use]
pub fn platform_type(browser_name: &str) -> PlatformType {
    let normalized = browser_name.to_ascii_uppercase().replace('-', "_");
    PlatformType::from_str_name(&normalized).unwrap_or(PlatformType::Chrome)
}

#[must_use]
pub fn web_sub_platform(browser: &Browser, sync_full_history: bool) -> WebSubPlatform {
    if !sync_full_history || browser.name != "Desktop" {
        return WebSubPlatform::WebBrowser;
    }

    match browser.os.as_str() {
        "Mac OS" => WebSubPlatform::Darwin,
        "Windows" => WebSubPlatform::Win32,
        _ => WebSubPlatform::WebBrowser,
    }
}

pub fn encode_big_endian(value: u32, width: usize) -> CoreResult<Bytes> {
    if width == 0 || width > 4 {
        return Err(CoreError::Payload(format!(
            "invalid big-endian width: {width}"
        )));
    }

    let max = if width == 4 {
        u32::MAX
    } else {
        (1u32 << (width * 8)) - 1
    };
    if value > max {
        return Err(CoreError::Payload(format!(
            "value {value} does not fit in {width} bytes"
        )));
    }

    let mut out = vec![0u8; width];
    for (index, byte) in out.iter_mut().enumerate() {
        let shift = (width - 1 - index) * 8;
        *byte = ((value >> shift) & 0xff) as u8;
    }
    Ok(Bytes::from(out))
}

#[must_use]
pub fn version_hash(version: WaVersion) -> Bytes {
    let value = format!("{}.{}.{}", version.0, version.1, version.2);
    Bytes::copy_from_slice(&Md5::digest(value.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn login_payload_uses_jid_and_config() {
        let config = ClientConfig {
            push_name: Some("rust-client".to_owned()),
            ..ClientConfig::default()
        };

        let payload = build_login_payload("12345:7@s.whatsapp.net", &config).unwrap();

        assert_eq!(payload.passive, Some(true));
        assert_eq!(payload.pull, Some(true));
        assert_eq!(payload.username, Some(12345));
        assert_eq!(payload.device, Some(7));
        assert_eq!(payload.lid_db_migrated, Some(false));
        assert_eq!(payload.push_name.as_deref(), Some("rust-client"));
        assert_eq!(payload.connect_type, Some(ConnectType::WifiUnknown as i32));
    }

    #[test]
    fn login_payload_rejects_invalid_jids() {
        assert!(build_login_payload("not-a-jid", &ClientConfig::default()).is_err());
        assert!(build_login_payload("abc@s.whatsapp.net", &ClientConfig::default()).is_err());
    }

    #[test]
    fn registration_payload_encodes_key_bundle() {
        let config = ClientConfig::default();
        let payload = build_registration_payload(
            RegistrationPayloadKeys {
                registration_id: 0x0102_0304,
                signed_identity_public: Bytes::from_static(b"identity"),
                signed_pre_key_id: 0x0001_0203,
                signed_pre_key_public: Bytes::from_static(b"pre-key"),
                signed_pre_key_signature: Bytes::from_static(b"signature"),
            },
            &config,
        )
        .unwrap();

        let data = payload.device_pairing_data.unwrap();
        assert_eq!(data.e_regid.unwrap(), Bytes::from_static(&[1, 2, 3, 4]));
        assert_eq!(
            data.e_keytype.unwrap(),
            Bytes::from_static(&KEY_BUNDLE_TYPE)
        );
        assert_eq!(data.e_ident.unwrap(), Bytes::from_static(b"identity"));
        assert_eq!(data.e_skey_id.unwrap(), Bytes::from_static(&[1, 2, 3]));
        assert_eq!(data.e_skey_val.unwrap(), Bytes::from_static(b"pre-key"));
        assert_eq!(data.e_skey_sig.unwrap(), Bytes::from_static(b"signature"));
        assert_eq!(data.build_hash.unwrap(), version_hash(config.version));

        let device_props = DeviceProps::decode(data.device_props.unwrap()).unwrap();
        assert_eq!(device_props.os.as_deref(), Some("Mac OS"));
        assert_eq!(
            device_props.platform_type,
            Some(PlatformType::Chrome as i32)
        );
        assert_eq!(device_props.require_full_sync, Some(true));
        let history = device_props.history_sync_config.unwrap();
        assert_eq!(history.storage_quota_mb, Some(10240));
        assert_eq!(history.inline_initial_payload_in_e2_ee_msg, Some(true));
        assert_eq!(history.support_group_history, Some(false));
    }

    #[test]
    fn registration_payload_rejects_oversized_pre_key_id() {
        let result = build_registration_payload(
            RegistrationPayloadKeys {
                registration_id: 1,
                signed_identity_public: Bytes::new(),
                signed_pre_key_id: 0x0100_0000,
                signed_pre_key_public: Bytes::new(),
                signed_pre_key_signature: Bytes::new(),
            },
            &ClientConfig::default(),
        );

        assert!(result.is_err());
    }

    #[test]
    fn maps_desktop_subplatforms_only_for_full_history_desktop() {
        let config = ClientConfig {
            browser: Browser::macos_desktop(),
            ..ClientConfig::default()
        };
        assert_eq!(
            web_info(&config).web_sub_platform,
            Some(WebSubPlatform::Darwin as i32)
        );

        let config = ClientConfig {
            sync_full_history: false,
            browser: Browser::macos_desktop(),
            ..ClientConfig::default()
        };
        assert_eq!(
            web_info(&config).web_sub_platform,
            Some(WebSubPlatform::WebBrowser as i32)
        );
    }

    #[test]
    fn encodes_big_endian_with_width_validation() {
        assert_eq!(
            encode_big_endian(0x0102, 4).unwrap(),
            Bytes::from_static(&[0, 0, 1, 2])
        );
        assert_eq!(
            encode_big_endian(0x0102, 2).unwrap(),
            Bytes::from_static(&[1, 2])
        );
        assert!(encode_big_endian(0x0100, 1).is_err());
        assert!(encode_big_endian(1, 0).is_err());
    }
}
