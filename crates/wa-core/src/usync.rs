use crate::message::MessageRelayRecipient;
use crate::{CoreError, CoreResult};
use bytes::Bytes;
use wa_binary::jid::S_WHATSAPP_NET;
use wa_binary::{BinaryNode, BinaryNodeContent};
use wa_binary::{JidServer, WaJidDomain, jid_decode, jid_encode};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct USyncUser {
    pub id: Option<String>,
    pub lid: Option<String>,
    pub phone: Option<String>,
    pub username: Option<String>,
    pub username_key: Option<String>,
    pub contact_type: Option<String>,
    pub persona_id: Option<String>,
}

impl USyncUser {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_id(mut self, id: impl Into<String>) -> Self {
        self.id = Some(id.into());
        self
    }

    #[must_use]
    pub fn with_lid(mut self, lid: impl Into<String>) -> Self {
        self.lid = Some(lid.into());
        self
    }

    #[must_use]
    pub fn with_phone(mut self, phone: impl Into<String>) -> Self {
        self.phone = Some(phone.into());
        self
    }

    #[must_use]
    pub fn with_username(mut self, username: impl Into<String>) -> Self {
        self.username = Some(username.into());
        self
    }

    #[must_use]
    pub fn with_username_key(mut self, username_key: impl Into<String>) -> Self {
        self.username_key = Some(username_key.into());
        self
    }

    #[must_use]
    pub fn with_contact_type(mut self, contact_type: impl Into<String>) -> Self {
        self.contact_type = Some(contact_type.into());
        self
    }

    #[must_use]
    pub fn with_persona_id(mut self, persona_id: impl Into<String>) -> Self {
        self.persona_id = Some(persona_id.into());
        self
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum USyncProtocol {
    Contact,
    Devices,
    Status,
    DisappearingMode,
    BotProfile,
    Lid,
    Username,
}

impl USyncProtocol {
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Contact => "contact",
            Self::Devices => "devices",
            Self::Status => "status",
            Self::DisappearingMode => "disappearing_mode",
            Self::BotProfile => "bot",
            Self::Lid => "lid",
            Self::Username => "username",
        }
    }

    #[must_use]
    pub fn query_element(self) -> BinaryNode {
        match self {
            Self::Devices => BinaryNode::new(self.name()).with_attr("version", "2"),
            Self::BotProfile => BinaryNode::new(self.name())
                .with_content(vec![BinaryNode::new("profile").with_attr("v", "1")]),
            _ => BinaryNode::new(self.name()),
        }
    }

    #[must_use]
    pub fn user_element(self, user: &USyncUser) -> Option<BinaryNode> {
        match self {
            Self::Contact => Some(contact_user_element(user)),
            Self::Lid => user
                .lid
                .as_ref()
                .map(|lid| BinaryNode::new("lid").with_attr("jid", lid)),
            Self::BotProfile => Some(BinaryNode::new("bot").with_content(vec![
                BinaryNode::new("profile").with_attr(
                    "persona_id",
                    user.persona_id.as_deref().unwrap_or_default(),
                ),
            ])),
            Self::Devices | Self::Status | Self::DisappearingMode | Self::Username => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct USyncQuery {
    pub protocols: Vec<USyncProtocol>,
    pub users: Vec<USyncUser>,
    pub context: String,
    pub mode: String,
}

impl Default for USyncQuery {
    fn default() -> Self {
        Self {
            protocols: Vec::new(),
            users: Vec::new(),
            context: "interactive".to_owned(),
            mode: "query".to_owned(),
        }
    }
}

impl USyncQuery {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_mode(mut self, mode: impl Into<String>) -> Self {
        self.mode = mode.into();
        self
    }

    #[must_use]
    pub fn with_context(mut self, context: impl Into<String>) -> Self {
        self.context = context.into();
        self
    }

    #[must_use]
    pub fn with_user(mut self, user: USyncUser) -> Self {
        self.users.push(user);
        self
    }

    #[must_use]
    pub fn with_protocol(mut self, protocol: USyncProtocol) -> Self {
        self.protocols.push(protocol);
        self
    }

    #[must_use]
    pub fn with_contact_protocol(self) -> Self {
        self.with_protocol(USyncProtocol::Contact)
    }

    #[must_use]
    pub fn with_device_protocol(self) -> Self {
        self.with_protocol(USyncProtocol::Devices)
    }

    #[must_use]
    pub fn with_status_protocol(self) -> Self {
        self.with_protocol(USyncProtocol::Status)
    }

    #[must_use]
    pub fn with_disappearing_mode_protocol(self) -> Self {
        self.with_protocol(USyncProtocol::DisappearingMode)
    }

    #[must_use]
    pub fn with_bot_profile_protocol(self) -> Self {
        self.with_protocol(USyncProtocol::BotProfile)
    }

    #[must_use]
    pub fn with_lid_protocol(self) -> Self {
        self.with_protocol(USyncProtocol::Lid)
    }

    #[must_use]
    pub fn with_username_protocol(self) -> Self {
        self.with_protocol(USyncProtocol::Username)
    }

    pub fn to_node(&self, tag: impl Into<String>) -> CoreResult<BinaryNode> {
        if self.protocols.is_empty() {
            return Err(CoreError::Protocol(
                "USync query must include at least one protocol".to_owned(),
            ));
        }
        let tag = tag.into();

        let user_nodes = self
            .users
            .iter()
            .map(|user| {
                let mut node = BinaryNode::new("user");
                if let Some(id) = &user.id
                    && user.phone.is_none()
                {
                    node = node.with_attr("jid", id);
                }
                let protocol_nodes = self
                    .protocols
                    .iter()
                    .filter_map(|protocol| protocol.user_element(user))
                    .collect::<Vec<_>>();
                if protocol_nodes.is_empty() {
                    node
                } else {
                    node.with_content(protocol_nodes)
                }
            })
            .collect::<Vec<_>>();

        Ok(BinaryNode::new("iq")
            .with_attr("id", tag.clone())
            .with_attr("to", S_WHATSAPP_NET)
            .with_attr("type", "get")
            .with_attr("xmlns", "usync")
            .with_content(vec![
                BinaryNode::new("usync")
                    .with_attr("context", self.context.clone())
                    .with_attr("mode", self.mode.clone())
                    .with_attr("sid", tag)
                    .with_attr("last", "true")
                    .with_attr("index", "0")
                    .with_content(vec![
                        BinaryNode::new("query").with_content(
                            self.protocols
                                .iter()
                                .map(|protocol| protocol.query_element())
                                .collect::<Vec<_>>(),
                        ),
                        BinaryNode::new("list").with_content(user_nodes),
                    ]),
            ]))
    }

    pub fn parse_result(&self, node: &BinaryNode) -> CoreResult<Option<USyncQueryResult>> {
        parse_usync_result(node)
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct USyncQueryResult {
    pub list: Vec<USyncUserResult>,
    pub side_list: Vec<USyncUserResult>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct USyncUserResult {
    pub id: String,
    pub contact: Option<bool>,
    pub devices: Option<USyncDeviceInfo>,
    pub status: Option<USyncStatus>,
    pub disappearing_mode: Option<USyncDisappearingMode>,
    pub bot_profile: Option<USyncBotProfile>,
    pub lid: Option<String>,
    pub username: Option<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct USyncDeviceInfo {
    pub device_list: Vec<USyncDevice>,
    pub key_index: Option<USyncKeyIndex>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct USyncDevice {
    pub id: u32,
    pub key_index: Option<u32>,
    pub is_hosted: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct USyncKeyIndex {
    pub timestamp: u64,
    pub signed_key_index: Option<Bytes>,
    pub expected_timestamp: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct USyncStatus {
    pub status: Option<String>,
    pub set_at: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct USyncDisappearingMode {
    pub duration: u32,
    pub set_at: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct USyncStatusResult {
    pub jid: String,
    pub status: USyncStatus,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct USyncDisappearingModeResult {
    pub jid: String,
    pub mode: USyncDisappearingMode,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct USyncBotProfileCommand {
    pub name: String,
    pub description: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct USyncBotProfile {
    pub jid: String,
    pub name: Option<String>,
    pub attributes: Option<String>,
    pub description: Option<String>,
    pub category: Option<String>,
    pub is_default: bool,
    pub prompts: Vec<String>,
    pub persona_id: Option<String>,
    pub commands: Vec<USyncBotProfileCommand>,
    pub commands_description: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OnWhatsAppResult {
    pub jid: String,
    pub exists: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct USyncLidMapping {
    pub pn: String,
    pub lid: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct USyncDeviceJid {
    pub jid: String,
    pub key_index: Option<u32>,
    pub is_hosted: bool,
}

pub fn build_on_whatsapp_query<I, T>(phone_numbers: I) -> CoreResult<Option<USyncQuery>>
where
    I: IntoIterator<Item = T>,
    T: AsRef<str>,
{
    let mut query = USyncQuery::new().with_contact_protocol();
    for phone_number in phone_numbers {
        let phone = normalize_phone_number(phone_number.as_ref())?;
        if !phone.is_empty() {
            query = query.with_user(USyncUser::new().with_phone(format!("+{phone}")));
        }
    }

    if query.users.is_empty() {
        Ok(None)
    } else {
        Ok(Some(query))
    }
}

#[must_use]
pub fn on_whatsapp_from_result(result: &USyncQueryResult) -> Vec<OnWhatsAppResult> {
    result
        .list
        .iter()
        .filter_map(|item| {
            item.contact.map(|exists| OnWhatsAppResult {
                jid: item.id.clone(),
                exists,
            })
        })
        .collect()
}

pub fn build_lid_mapping_query<I, T>(jids: I) -> CoreResult<Option<USyncQuery>>
where
    I: IntoIterator<Item = T>,
    T: AsRef<str>,
{
    let mut query = USyncQuery::new()
        .with_context("background")
        .with_lid_protocol();
    for jid in jids {
        let jid = jid.as_ref();
        if jid_decode(jid).is_none() {
            return Err(CoreError::Protocol(format!(
                "invalid JID for LID query: {jid}"
            )));
        }
        query = query.with_user(USyncUser::new().with_id(jid));
    }

    if query.users.is_empty() {
        Ok(None)
    } else {
        Ok(Some(query))
    }
}

#[must_use]
pub fn lid_mappings_from_result(result: &USyncQueryResult) -> Vec<USyncLidMapping> {
    result
        .list
        .iter()
        .filter_map(|item| {
            item.lid.as_ref().map(|lid| USyncLidMapping {
                pn: item.id.clone(),
                lid: lid.clone(),
            })
        })
        .collect()
}

pub fn build_device_query<I, T>(jids: I) -> CoreResult<Option<USyncQuery>>
where
    I: IntoIterator<Item = T>,
    T: AsRef<str>,
{
    let mut query = USyncQuery::new().with_device_protocol();
    for jid in jids {
        let jid = jid.as_ref();
        if jid_decode(jid).is_none() {
            return Err(CoreError::Protocol(format!(
                "invalid JID for device query: {jid}"
            )));
        }
        query = query.with_user(USyncUser::new().with_id(jid));
    }

    if query.users.is_empty() {
        Ok(None)
    } else {
        Ok(Some(query))
    }
}

pub fn build_status_query<I, T>(jids: I) -> CoreResult<Option<USyncQuery>>
where
    I: IntoIterator<Item = T>,
    T: AsRef<str>,
{
    build_jid_protocol_query(jids, USyncProtocol::Status, "status")
}

#[must_use]
pub fn statuses_from_result(result: &USyncQueryResult) -> Vec<USyncStatusResult> {
    result
        .list
        .iter()
        .filter_map(|item| {
            item.status.as_ref().map(|status| USyncStatusResult {
                jid: item.id.clone(),
                status: status.clone(),
            })
        })
        .collect()
}

pub fn build_disappearing_mode_query<I, T>(jids: I) -> CoreResult<Option<USyncQuery>>
where
    I: IntoIterator<Item = T>,
    T: AsRef<str>,
{
    build_jid_protocol_query(jids, USyncProtocol::DisappearingMode, "disappearing mode")
}

#[must_use]
pub fn disappearing_modes_from_result(
    result: &USyncQueryResult,
) -> Vec<USyncDisappearingModeResult> {
    result
        .list
        .iter()
        .filter_map(|item| {
            item.disappearing_mode
                .as_ref()
                .map(|mode| USyncDisappearingModeResult {
                    jid: item.id.clone(),
                    mode: mode.clone(),
                })
        })
        .collect()
}

pub fn build_bot_profile_query<I, J, P>(profiles: I) -> CoreResult<Option<USyncQuery>>
where
    I: IntoIterator<Item = (J, P)>,
    J: AsRef<str>,
    P: AsRef<str>,
{
    let mut query = USyncQuery::new().with_bot_profile_protocol();
    for (jid, persona_id) in profiles {
        let jid = jid.as_ref();
        if jid_decode(jid).is_none() {
            return Err(CoreError::Protocol(format!(
                "invalid JID for bot profile query: {jid}"
            )));
        }
        let persona_id = persona_id.as_ref().trim();
        if persona_id.is_empty() {
            return Err(CoreError::Protocol(
                "bot profile query requires persona id".to_owned(),
            ));
        }
        query = query.with_user(USyncUser::new().with_id(jid).with_persona_id(persona_id));
    }

    if query.users.is_empty() {
        Ok(None)
    } else {
        Ok(Some(query))
    }
}

#[must_use]
pub fn bot_profiles_from_result(result: &USyncQueryResult) -> Vec<USyncBotProfile> {
    result
        .list
        .iter()
        .filter_map(|item| item.bot_profile.clone())
        .collect()
}

pub fn extract_device_jids(
    result: &USyncQueryResult,
    my_jid: &str,
    my_lid: Option<&str>,
    exclude_zero_devices: bool,
) -> CoreResult<Vec<USyncDeviceJid>> {
    let my = jid_decode(my_jid)
        .ok_or_else(|| CoreError::Protocol(format!("invalid own JID: {my_jid}")))?;
    let my_lid_user = my_lid.and_then(jid_decode).map(|jid| jid.user);
    let mut out = Vec::new();

    for user in &result.list {
        let decoded = jid_decode(&user.id).ok_or_else(|| {
            CoreError::Protocol(format!("invalid device result JID: {}", user.id))
        })?;
        let Some(devices) = &user.devices else {
            continue;
        };
        for device in &devices.device_list {
            if exclude_zero_devices && device.id == 0 {
                continue;
            }
            let is_own_user = my.user == decoded.user
                || my_lid_user
                    .as_ref()
                    .is_some_and(|lid_user| lid_user == &decoded.user);
            if is_own_user && u32::from(my.device.unwrap_or(0)) == device.id {
                continue;
            }
            if device.id != 0 && device.key_index.is_none() {
                continue;
            }

            out.push(USyncDeviceJid {
                jid: encode_device_jid(&decoded.user, decoded.server, decoded.domain_type, device)?,
                key_index: device.key_index,
                is_hosted: device.is_hosted,
            });
        }
    }

    Ok(out)
}

pub fn relay_recipients_from_device_jids(
    devices: &[USyncDeviceJid],
    my_jid: &str,
    my_lid: Option<&str>,
) -> CoreResult<Vec<MessageRelayRecipient>> {
    let my = jid_decode(my_jid)
        .ok_or_else(|| CoreError::Protocol(format!("invalid own JID: {my_jid}")))?;
    let my_lid_user = my_lid
        .map(|lid| {
            jid_decode(lid)
                .map(|jid| jid.user)
                .ok_or_else(|| CoreError::Protocol(format!("invalid own LID: {lid}")))
        })
        .transpose()?;
    let my_device = u32::from(my.device.unwrap_or(0));
    let mut recipients = Vec::with_capacity(devices.len());

    for device in devices {
        let decoded = jid_decode(&device.jid).ok_or_else(|| {
            CoreError::Protocol(format!("invalid discovered device JID: {}", device.jid))
        })?;
        let is_own_user = decoded.user == my.user
            || my_lid_user
                .as_ref()
                .is_some_and(|lid_user| lid_user == &decoded.user);
        if is_own_user && u32::from(decoded.device.unwrap_or(0)) == my_device {
            continue;
        }

        recipients.push(if is_own_user {
            MessageRelayRecipient::own_device(device.jid.clone())
        } else {
            MessageRelayRecipient::new(device.jid.clone())
        });
    }

    Ok(recipients)
}

fn build_jid_protocol_query<I, T>(
    jids: I,
    protocol: USyncProtocol,
    label: &str,
) -> CoreResult<Option<USyncQuery>>
where
    I: IntoIterator<Item = T>,
    T: AsRef<str>,
{
    let mut query = USyncQuery::new().with_protocol(protocol);
    for jid in jids {
        let jid = jid.as_ref();
        if jid_decode(jid).is_none() {
            return Err(CoreError::Protocol(format!(
                "invalid JID for {label} query: {jid}"
            )));
        }
        query = query.with_user(USyncUser::new().with_id(jid));
    }

    if query.users.is_empty() {
        Ok(None)
    } else {
        Ok(Some(query))
    }
}

pub fn parse_usync_result(node: &BinaryNode) -> CoreResult<Option<USyncQueryResult>> {
    if let Some(error) = usync_error_from_result(node) {
        return Err(error);
    }

    if node.attrs.get("type").is_none_or(|value| value != "result") {
        return Ok(None);
    }
    let Some(usync) = child_node(node, "usync") else {
        return Ok(Some(USyncQueryResult::default()));
    };

    Ok(Some(USyncQueryResult {
        list: parse_result_list(child_node(usync, "list"))?,
        side_list: parse_result_list(child_node(usync, "side_list"))?,
    }))
}

fn usync_error_from_result(node: &BinaryNode) -> Option<CoreError> {
    let error_node = child_node(node, "error");
    if node.attrs.get("type").is_none_or(|value| value != "error") && error_node.is_none() {
        return None;
    }
    let code = error_node
        .and_then(|error| error.attrs.get("code"))
        .or_else(|| node.attrs.get("code"))
        .or_else(|| node.attrs.get("error"))
        .map(String::as_str)
        .unwrap_or("500");
    let text = error_node
        .and_then(|error| error.attrs.get("text"))
        .or_else(|| node.attrs.get("text"))
        .or_else(|| node.attrs.get("reason"))
        .map(String::as_str)
        .unwrap_or("USync query failed");
    Some(CoreError::Protocol(format!(
        "USync query failed ({code}): {text}"
    )))
}

fn encode_device_jid(
    user: &str,
    server: JidServer,
    domain_type: WaJidDomain,
    device: &USyncDevice,
) -> CoreResult<String> {
    let server = if device.is_hosted {
        if domain_type == WaJidDomain::Lid || server == JidServer::Lid {
            JidServer::HostedLid
        } else {
            JidServer::Hosted
        }
    } else {
        domain_type.server(server)
    };
    let device_id = if device.id == 0 {
        None
    } else {
        Some(
            u16::try_from(device.id)
                .map_err(|_| CoreError::Protocol("device id exceeds u16".to_owned()))?,
        )
    };
    Ok(jid_encode(user, server, device_id, None))
}

fn normalize_phone_number(phone_number: &str) -> CoreResult<String> {
    let phone_number = phone_number.trim().trim_start_matches('+');
    let mut normalized = String::with_capacity(phone_number.len());
    for ch in phone_number.chars() {
        if ch.is_ascii_digit() {
            normalized.push(ch);
        } else if ch == ' ' || ch == '-' {
            continue;
        } else {
            return Err(CoreError::Protocol(format!(
                "invalid phone number character: {ch}"
            )));
        }
    }
    Ok(normalized)
}

fn contact_user_element(user: &USyncUser) -> BinaryNode {
    if let Some(phone) = &user.phone {
        return BinaryNode::new("contact").with_content(phone.clone());
    }
    if let Some(username) = &user.username {
        let mut node = BinaryNode::new("contact").with_attr("username", username);
        if let Some(username_key) = &user.username_key {
            node = node.with_attr("pin", username_key);
        }
        if let Some(lid) = &user.lid {
            node = node.with_attr("lid", lid);
        }
        return node;
    }
    if let Some(contact_type) = &user.contact_type {
        return BinaryNode::new("contact").with_attr("type", contact_type);
    }
    BinaryNode::new("contact")
}

fn parse_result_list(node: Option<&BinaryNode>) -> CoreResult<Vec<USyncUserResult>> {
    let Some(node) = node else {
        return Ok(Vec::new());
    };
    let Some(BinaryNodeContent::Nodes(users)) = &node.content else {
        return Ok(Vec::new());
    };

    users
        .iter()
        .filter(|node| node.tag == "user")
        .map(parse_user_result)
        .collect()
}

fn parse_user_result(node: &BinaryNode) -> CoreResult<USyncUserResult> {
    let id = node
        .attrs
        .get("jid")
        .cloned()
        .ok_or_else(|| CoreError::Protocol("USync result user missing jid".to_owned()))?;
    let mut result = USyncUserResult {
        id,
        ..USyncUserResult::default()
    };

    let Some(BinaryNodeContent::Nodes(children)) = &node.content else {
        return Ok(result);
    };
    for child in children {
        match child.tag.as_str() {
            "contact" => result.contact = Some(child.attrs.get("type").is_some_and(|v| v == "in")),
            "devices" => result.devices = Some(parse_devices(child)?),
            "status" => result.status = Some(parse_status(child)?),
            "disappearing_mode" => {
                result.disappearing_mode = Some(parse_disappearing_mode(child)?);
            }
            "bot" => {
                result.bot_profile = Some(parse_bot_profile(&result.id, child)?);
            }
            "lid" => result.lid = child.attrs.get("val").cloned(),
            "username" => result.username = node_text(child)?,
            _ => {}
        }
    }

    Ok(result)
}

fn parse_devices(node: &BinaryNode) -> CoreResult<USyncDeviceInfo> {
    let mut device_list = Vec::new();
    if let Some(list_node) = child_node(node, "device-list")
        && let Some(BinaryNodeContent::Nodes(devices)) = &list_node.content
    {
        for device in devices.iter().filter(|node| node.tag == "device") {
            let id = required_attr_u32(device, "id")?;
            let key_index = optional_attr_u32(device, "key-index")?;
            let is_hosted = device
                .attrs
                .get("is_hosted")
                .is_some_and(|value| value == "true");
            device_list.push(USyncDevice {
                id,
                key_index,
                is_hosted,
            });
        }
    }

    let key_index = child_node(node, "key-index-list")
        .map(|node| {
            Ok::<_, CoreError>(USyncKeyIndex {
                timestamp: required_attr_u64(node, "ts")?,
                signed_key_index: node_bytes(node),
                expected_timestamp: optional_attr_u64(node, "expected_ts")?,
            })
        })
        .transpose()?;

    Ok(USyncDeviceInfo {
        device_list,
        key_index,
    })
}

fn parse_status(node: &BinaryNode) -> CoreResult<USyncStatus> {
    let mut status = node_text(node)?;
    if status.as_deref() == Some("") {
        status = None;
    }
    if status.is_none() && node.attrs.get("code").is_some_and(|code| code == "401") {
        status = Some(String::new());
    }
    Ok(USyncStatus {
        status,
        set_at: optional_attr_u64(node, "t")?,
    })
}

fn parse_disappearing_mode(node: &BinaryNode) -> CoreResult<USyncDisappearingMode> {
    Ok(USyncDisappearingMode {
        duration: required_attr_u32(node, "duration")?,
        set_at: optional_attr_u64(node, "t")?,
    })
}

fn parse_bot_profile(jid: &str, node: &BinaryNode) -> CoreResult<USyncBotProfile> {
    let profile = child_node(node, "profile");
    let commands_node = profile.and_then(|profile| child_node(profile, "commands"));
    let prompts_node = profile.and_then(|profile| child_node(profile, "prompts"));

    let commands = node_children(commands_node, "command")
        .into_iter()
        .filter_map(|command| {
            let name = child_text(command, "name").unwrap_or_default();
            let description = child_text(command, "description").unwrap_or_default();
            if name.is_empty() && description.is_empty() {
                None
            } else {
                Some(USyncBotProfileCommand { name, description })
            }
        })
        .collect::<Vec<_>>();

    let prompts = node_children(prompts_node, "prompt")
        .into_iter()
        .filter_map(|prompt| {
            let emoji = child_text(prompt, "emoji").unwrap_or_default();
            let text = child_text(prompt, "text").unwrap_or_default();
            let prompt = match (emoji.is_empty(), text.is_empty()) {
                (true, true) => String::new(),
                (true, false) => text,
                (false, true) => emoji,
                (false, false) => format!("{emoji} {text}"),
            };
            if prompt.is_empty() {
                None
            } else {
                Some(prompt)
            }
        })
        .collect::<Vec<_>>();

    Ok(USyncBotProfile {
        jid: jid.to_owned(),
        name: profile.and_then(|profile| child_text(profile, "name")),
        attributes: profile.and_then(|profile| child_text(profile, "attributes")),
        description: profile.and_then(|profile| child_text(profile, "description")),
        category: profile.and_then(|profile| child_text(profile, "category")),
        is_default: profile
            .and_then(|profile| child_node(profile, "default"))
            .is_some(),
        prompts,
        persona_id: profile.and_then(|profile| profile.attrs.get("persona_id").cloned()),
        commands,
        commands_description: commands_node.and_then(|node| child_text(node, "description")),
    })
}

fn child_node<'a>(node: &'a BinaryNode, tag: &str) -> Option<&'a BinaryNode> {
    let Some(BinaryNodeContent::Nodes(children)) = &node.content else {
        return None;
    };
    children.iter().find(|child| child.tag == tag)
}

fn node_children<'a>(node: Option<&'a BinaryNode>, tag: &str) -> Vec<&'a BinaryNode> {
    let Some(node) = node else {
        return Vec::new();
    };
    let Some(BinaryNodeContent::Nodes(children)) = &node.content else {
        return Vec::new();
    };
    children.iter().filter(|child| child.tag == tag).collect()
}

fn child_text(node: &BinaryNode, tag: &str) -> Option<String> {
    child_node(node, tag).and_then(|child| node_text(child).ok().flatten())
}

fn node_text(node: &BinaryNode) -> CoreResult<Option<String>> {
    match &node.content {
        None => Ok(None),
        Some(BinaryNodeContent::Text(value)) => Ok(Some(value.clone())),
        Some(BinaryNodeContent::Bytes(value)) => String::from_utf8(value.to_vec())
            .map(Some)
            .map_err(|err| CoreError::Protocol(format!("invalid USync text: {err}"))),
        Some(BinaryNodeContent::Nodes(_)) => Ok(None),
    }
}

fn node_bytes(node: &BinaryNode) -> Option<Bytes> {
    match &node.content {
        Some(BinaryNodeContent::Bytes(value)) => Some(value.clone()),
        Some(BinaryNodeContent::Text(value)) => Some(Bytes::copy_from_slice(value.as_bytes())),
        _ => None,
    }
}

fn required_attr_u32(node: &BinaryNode, attr: &str) -> CoreResult<u32> {
    node.attrs
        .get(attr)
        .ok_or_else(|| CoreError::Protocol(format!("missing USync attribute {attr}")))?
        .parse::<u32>()
        .map_err(|err| CoreError::Protocol(format!("invalid USync attribute {attr}: {err}")))
}

fn optional_attr_u32(node: &BinaryNode, attr: &str) -> CoreResult<Option<u32>> {
    node.attrs
        .get(attr)
        .map(|value| {
            value.parse::<u32>().map_err(|err| {
                CoreError::Protocol(format!("invalid USync attribute {attr}: {err}"))
            })
        })
        .transpose()
}

fn required_attr_u64(node: &BinaryNode, attr: &str) -> CoreResult<u64> {
    node.attrs
        .get(attr)
        .ok_or_else(|| CoreError::Protocol(format!("missing USync attribute {attr}")))?
        .parse::<u64>()
        .map_err(|err| CoreError::Protocol(format!("invalid USync attribute {attr}: {err}")))
}

fn optional_attr_u64(node: &BinaryNode, attr: &str) -> CoreResult<Option<u64>> {
    node.attrs
        .get(attr)
        .map(|value| {
            value.parse::<u64>().map_err(|err| {
                CoreError::Protocol(format!("invalid USync attribute {attr}: {err}"))
            })
        })
        .transpose()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_usync_query_node() {
        let query = USyncQuery::new()
            .with_context("background")
            .with_contact_protocol()
            .with_device_protocol()
            .with_lid_protocol()
            .with_user(
                USyncUser::new()
                    .with_id("123@s.whatsapp.net")
                    .with_phone("+123")
                    .with_lid("abc@lid"),
            );

        let node = query.to_node("usync-1").unwrap();
        assert_eq!(node.tag, "iq");
        assert_eq!(node.attrs["id"], "usync-1");
        assert_eq!(node.attrs["to"], S_WHATSAPP_NET);
        assert_eq!(node.attrs["xmlns"], "usync");
        let usync = child_node(&node, "usync").unwrap();
        assert_eq!(usync.attrs["context"], "background");
        assert_eq!(usync.attrs["sid"], "usync-1");
        let query_node = child_node(usync, "query").unwrap();
        assert!(child_node(query_node, "contact").is_some());
        assert!(child_node(query_node, "devices").is_some());
        assert!(child_node(query_node, "lid").is_some());
        let list = child_node(usync, "list").unwrap();
        let user = child_node(list, "user").unwrap();
        assert!(!user.attrs.contains_key("jid"));
        assert_eq!(
            child_node(user, "contact").unwrap().content,
            Some(BinaryNodeContent::Text("+123".to_owned()))
        );
        assert_eq!(child_node(user, "lid").unwrap().attrs["jid"], "abc@lid");
    }

    #[test]
    fn parses_usync_result_nodes() {
        let result = BinaryNode::new("iq")
            .with_attr("type", "result")
            .with_content(vec![BinaryNode::new("usync").with_content(vec![
                BinaryNode::new("list").with_content(vec![BinaryNode::new("user")
                    .with_attr("jid", "123@s.whatsapp.net")
                    .with_content(vec![
                        BinaryNode::new("contact").with_attr("type", "in"),
                        BinaryNode::new("devices").with_content(vec![
                            BinaryNode::new("device-list").with_content(vec![
                                BinaryNode::new("device")
                                    .with_attr("id", "0")
                                    .with_attr("key-index", "11"),
                                BinaryNode::new("device")
                                    .with_attr("id", "99")
                                    .with_attr("key-index", "12")
                                    .with_attr("is_hosted", "true"),
                            ]),
                            BinaryNode::new("key-index-list")
                                .with_attr("ts", "100")
                                .with_attr("expected_ts", "101")
                                .with_content(Bytes::from_static(b"signed")),
                        ]),
                        BinaryNode::new("status")
                            .with_attr("t", "99")
                            .with_content("hello"),
                        BinaryNode::new("disappearing_mode")
                            .with_attr("duration", "86400")
                            .with_attr("t", "88"),
                        BinaryNode::new("lid").with_attr("val", "abc@lid"),
                        BinaryNode::new("username").with_content("handle"),
                    ])]),
            ])]);

        let parsed = parse_usync_result(&result).unwrap().unwrap();
        assert_eq!(parsed.list.len(), 1);
        let user = &parsed.list[0];
        assert_eq!(user.id, "123@s.whatsapp.net");
        assert_eq!(user.contact, Some(true));
        assert_eq!(user.devices.as_ref().unwrap().device_list.len(), 2);
        assert!(user.devices.as_ref().unwrap().device_list[1].is_hosted);
        assert_eq!(
            user.devices.as_ref().unwrap().key_index.as_ref().unwrap(),
            &USyncKeyIndex {
                timestamp: 100,
                signed_key_index: Some(Bytes::from_static(b"signed")),
                expected_timestamp: Some(101),
            }
        );
        assert_eq!(
            user.status.as_ref().unwrap().status.as_deref(),
            Some("hello")
        );
        assert_eq!(user.disappearing_mode.as_ref().unwrap().duration, 86400);
        assert_eq!(user.lid.as_deref(), Some("abc@lid"));
        assert_eq!(user.username.as_deref(), Some("handle"));
    }

    #[test]
    fn ignores_non_result_usync_nodes() {
        assert!(
            parse_usync_result(&BinaryNode::new("iq"))
                .unwrap()
                .is_none()
        );

        let attr_error = BinaryNode::new("iq")
            .with_attr("type", "error")
            .with_attr("code", "403")
            .with_attr("text", "not allowed");
        let err = parse_usync_result(&attr_error).unwrap_err();
        assert!(
            err.to_string()
                .contains("USync query failed (403): not allowed")
        );

        let child_error = BinaryNode::new("iq")
            .with_attr("type", "result")
            .with_content(vec![
                BinaryNode::new("error")
                    .with_attr("code", "500")
                    .with_attr("text", "try again"),
            ]);
        let err = parse_usync_result(&child_error).unwrap_err();
        assert!(
            err.to_string()
                .contains("USync query failed (500): try again")
        );
    }

    #[test]
    fn builds_on_whatsapp_query_and_maps_results() {
        let query = build_on_whatsapp_query(["+1 234-567", ""])
            .unwrap()
            .unwrap();
        assert_eq!(query.protocols, vec![USyncProtocol::Contact]);
        assert_eq!(query.users.len(), 1);
        assert_eq!(query.users[0].phone.as_deref(), Some("+1234567"));

        let result = USyncQueryResult {
            list: vec![
                USyncUserResult {
                    id: "123@s.whatsapp.net".to_owned(),
                    contact: Some(true),
                    ..USyncUserResult::default()
                },
                USyncUserResult {
                    id: "456@s.whatsapp.net".to_owned(),
                    contact: Some(false),
                    ..USyncUserResult::default()
                },
            ],
            side_list: Vec::new(),
        };
        assert_eq!(
            on_whatsapp_from_result(&result),
            vec![
                OnWhatsAppResult {
                    jid: "123@s.whatsapp.net".to_owned(),
                    exists: true,
                },
                OnWhatsAppResult {
                    jid: "456@s.whatsapp.net".to_owned(),
                    exists: false,
                },
            ]
        );
    }

    #[test]
    fn builds_lid_mapping_query_and_maps_results() {
        let query = build_lid_mapping_query(["123@s.whatsapp.net"])
            .unwrap()
            .unwrap();
        assert_eq!(query.context, "background");
        assert_eq!(query.protocols, vec![USyncProtocol::Lid]);
        assert_eq!(query.users[0].id.as_deref(), Some("123@s.whatsapp.net"));

        let result = USyncQueryResult {
            list: vec![USyncUserResult {
                id: "123@s.whatsapp.net".to_owned(),
                lid: Some("abc@lid".to_owned()),
                ..USyncUserResult::default()
            }],
            side_list: Vec::new(),
        };
        assert_eq!(
            lid_mappings_from_result(&result),
            vec![USyncLidMapping {
                pn: "123@s.whatsapp.net".to_owned(),
                lid: "abc@lid".to_owned(),
            }]
        );
    }

    #[test]
    fn builds_status_and_disappearing_queries_and_maps_results() {
        let status_query = build_status_query(["123@s.whatsapp.net"]).unwrap().unwrap();
        assert_eq!(status_query.protocols, vec![USyncProtocol::Status]);
        assert_eq!(
            status_query.users[0].id.as_deref(),
            Some("123@s.whatsapp.net")
        );

        let disappearing_query = build_disappearing_mode_query(["123@s.whatsapp.net"])
            .unwrap()
            .unwrap();
        assert_eq!(
            disappearing_query.protocols,
            vec![USyncProtocol::DisappearingMode]
        );

        let result = USyncQueryResult {
            list: vec![USyncUserResult {
                id: "123@s.whatsapp.net".to_owned(),
                status: Some(USyncStatus {
                    status: Some("available".to_owned()),
                    set_at: Some(11),
                }),
                disappearing_mode: Some(USyncDisappearingMode {
                    duration: 86400,
                    set_at: Some(12),
                }),
                ..USyncUserResult::default()
            }],
            side_list: Vec::new(),
        };
        assert_eq!(
            statuses_from_result(&result),
            vec![USyncStatusResult {
                jid: "123@s.whatsapp.net".to_owned(),
                status: USyncStatus {
                    status: Some("available".to_owned()),
                    set_at: Some(11),
                },
            }]
        );
        assert_eq!(
            disappearing_modes_from_result(&result),
            vec![USyncDisappearingModeResult {
                jid: "123@s.whatsapp.net".to_owned(),
                mode: USyncDisappearingMode {
                    duration: 86400,
                    set_at: Some(12),
                },
            }]
        );
    }

    #[test]
    fn builds_bot_profile_query_and_maps_profile_result() {
        let query = build_bot_profile_query([("123@s.whatsapp.net", "persona-1")])
            .unwrap()
            .unwrap();
        assert_eq!(query.protocols, vec![USyncProtocol::BotProfile]);
        assert_eq!(query.users[0].persona_id.as_deref(), Some("persona-1"));
        let node = query.to_node("usync-bot").unwrap();
        let usync = child_node(&node, "usync").unwrap();
        let query_node = child_node(usync, "query").unwrap();
        let bot_query = child_node(query_node, "bot").unwrap();
        assert_eq!(child_node(bot_query, "profile").unwrap().attrs["v"], "1");
        let list = child_node(usync, "list").unwrap();
        let user = child_node(list, "user").unwrap();
        let bot_user = child_node(user, "bot").unwrap();
        assert_eq!(
            child_node(bot_user, "profile").unwrap().attrs["persona_id"],
            "persona-1"
        );

        let result = BinaryNode::new("iq")
            .with_attr("type", "result")
            .with_content(vec![BinaryNode::new("usync").with_content(vec![
                BinaryNode::new("list").with_content(vec![BinaryNode::new("user")
                    .with_attr("jid", "123@s.whatsapp.net")
                    .with_content(vec![BinaryNode::new("bot").with_content(vec![
                        BinaryNode::new("profile")
                            .with_attr("persona_id", "persona-1")
                            .with_content(vec![
                                BinaryNode::new("default"),
                                BinaryNode::new("name").with_content("Helper"),
                                BinaryNode::new("attributes").with_content("fast"),
                                BinaryNode::new("description").with_content("Answers questions"),
                                BinaryNode::new("category").with_content("utility"),
                                BinaryNode::new("commands").with_content(vec![
                                    BinaryNode::new("description").with_content("Commands"),
                                    BinaryNode::new("command").with_content(vec![
                                        BinaryNode::new("name").with_content("/help"),
                                        BinaryNode::new("description").with_content("Show help"),
                                    ]),
                                ]),
                                BinaryNode::new("prompts").with_content(vec![
                                    BinaryNode::new("prompt").with_content(vec![
                                        BinaryNode::new("emoji").with_content("*"),
                                        BinaryNode::new("text").with_content("Start"),
                                    ]),
                                ]),
                            ]),
                    ])])]),
            ])]);

        let parsed = parse_usync_result(&result).unwrap().unwrap();
        assert_eq!(
            bot_profiles_from_result(&parsed),
            vec![USyncBotProfile {
                jid: "123@s.whatsapp.net".to_owned(),
                name: Some("Helper".to_owned()),
                attributes: Some("fast".to_owned()),
                description: Some("Answers questions".to_owned()),
                category: Some("utility".to_owned()),
                is_default: true,
                prompts: vec!["* Start".to_owned()],
                persona_id: Some("persona-1".to_owned()),
                commands: vec![USyncBotProfileCommand {
                    name: "/help".to_owned(),
                    description: "Show help".to_owned(),
                }],
                commands_description: Some("Commands".to_owned()),
            }]
        );
    }

    #[test]
    fn extracts_device_jids_with_hosted_domains_and_own_device_exclusion() {
        let result = USyncQueryResult {
            list: vec![
                USyncUserResult {
                    id: "123@s.whatsapp.net".to_owned(),
                    devices: Some(USyncDeviceInfo {
                        device_list: vec![
                            USyncDevice {
                                id: 0,
                                key_index: None,
                                is_hosted: false,
                            },
                            USyncDevice {
                                id: 7,
                                key_index: Some(1),
                                is_hosted: false,
                            },
                            USyncDevice {
                                id: 8,
                                key_index: None,
                                is_hosted: false,
                            },
                        ],
                        key_index: None,
                    }),
                    ..USyncUserResult::default()
                },
                USyncUserResult {
                    id: "abc@lid".to_owned(),
                    devices: Some(USyncDeviceInfo {
                        device_list: vec![USyncDevice {
                            id: 99,
                            key_index: Some(2),
                            is_hosted: true,
                        }],
                        key_index: None,
                    }),
                    ..USyncUserResult::default()
                },
            ],
            side_list: Vec::new(),
        };

        let devices =
            extract_device_jids(&result, "123:7@s.whatsapp.net", Some("abc@lid"), false).unwrap();
        assert_eq!(
            devices,
            vec![
                USyncDeviceJid {
                    jid: "123@s.whatsapp.net".to_owned(),
                    key_index: None,
                    is_hosted: false,
                },
                USyncDeviceJid {
                    jid: "abc:99@hosted.lid".to_owned(),
                    key_index: Some(2),
                    is_hosted: true,
                },
            ]
        );

        let devices = extract_device_jids(&result, "999@s.whatsapp.net", None, true).unwrap();
        assert!(
            !devices
                .iter()
                .any(|device| device.jid == "123@s.whatsapp.net")
        );
    }

    #[test]
    fn classifies_relay_recipients_from_discovered_devices() {
        let devices = vec![
            USyncDeviceJid {
                jid: "999:7@s.whatsapp.net".to_owned(),
                key_index: Some(1),
                is_hosted: false,
            },
            USyncDeviceJid {
                jid: "999@s.whatsapp.net".to_owned(),
                key_index: None,
                is_hosted: false,
            },
            USyncDeviceJid {
                jid: "ownlid:7@lid".to_owned(),
                key_index: Some(2),
                is_hosted: false,
            },
            USyncDeviceJid {
                jid: "ownlid:9@hosted.lid".to_owned(),
                key_index: Some(3),
                is_hosted: true,
            },
            USyncDeviceJid {
                jid: "123:1@s.whatsapp.net".to_owned(),
                key_index: Some(4),
                is_hosted: false,
            },
        ];

        let recipients =
            relay_recipients_from_device_jids(&devices, "999:7@s.whatsapp.net", Some("ownlid@lid"))
                .unwrap();

        assert_eq!(
            recipients,
            vec![
                MessageRelayRecipient::own_device("999@s.whatsapp.net"),
                MessageRelayRecipient::own_device("ownlid:9@hosted.lid"),
                MessageRelayRecipient::new("123:1@s.whatsapp.net"),
            ]
        );
    }

    #[test]
    fn relay_recipient_classification_rejects_invalid_jids() {
        assert!(relay_recipients_from_device_jids(&[], "invalid", None).is_err());
        assert!(
            relay_recipients_from_device_jids(&[], "999:7@s.whatsapp.net", Some("invalid"))
                .is_err()
        );
        assert!(
            relay_recipients_from_device_jids(
                &[USyncDeviceJid {
                    jid: "invalid".to_owned(),
                    key_index: None,
                    is_hosted: false,
                }],
                "999:7@s.whatsapp.net",
                None,
            )
            .is_err()
        );
    }
}
