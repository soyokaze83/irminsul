use crate::mex::{DEFAULT_MAX_WMEX_JSON_BYTES, build_wmex_query, parse_wmex_response};
use crate::{CoreError, CoreResult};
use serde_json::{Value, json};
use wa_binary::{BinaryNode, BinaryNodeContent};

const QUERY_REACHOUT_TIMELOCK: &str = "23983697327930364";
const QUERY_MESSAGE_CAPPING_INFO: &str = "24503548349331633";

const PATH_REACHOUT_TIMELOCK: &str = "xwa2_fetch_account_reachout_timelock";
const PATH_MESSAGE_CAPPING_INFO: &str = "xwa2_message_capping_info";
const PATH_NOTIFY_REACHOUT_TIMELOCK: &str = "xwa2_notify_account_reachout_timelock";
const PATH_NOTIFY_MESSAGE_CAPPING_INFO: &str = "xwa2_notify_new_chat_messages_capping_info_update";

const OP_REACHOUT_TIMELOCK_UPDATE: &str = "NotificationUserReachoutTimelockUpdate";
const OP_MESSAGE_CAPPING_INFO_UPDATE: &str = "MessageCappingInfoNotification";
const DEFAULT_REACHOUT_NOTIFICATION_SECONDS: u64 = 60;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AccountUpdate {
    ReachoutTimelock(ReachoutTimelockState),
    MessageCapping(MessageCappingInfo),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReachoutTimelockState {
    pub is_active: bool,
    pub time_enforcement_ends: Option<u64>,
    pub enforcement_type: ReachoutTimelockEnforcementType,
}

impl Default for ReachoutTimelockState {
    fn default() -> Self {
        Self {
            is_active: false,
            time_enforcement_ends: None,
            enforcement_type: ReachoutTimelockEnforcementType::Default,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReachoutTimelockEnforcementType {
    BizCommerceViolationAlcohol,
    BizCommerceViolationAdult,
    BizCommerceViolationAnimals,
    BizCommerceViolationBodyPartsFluids,
    BizCommerceViolationDating,
    BizCommerceViolationDigitalServicesProducts,
    BizCommerceViolationDrugs,
    BizCommerceViolationDrugsOnlyOtc,
    BizCommerceViolationGambling,
    BizCommerceViolationHealthcare,
    BizCommerceViolationRealFakeCurrency,
    BizCommerceViolationSupplements,
    BizCommerceViolationTobacco,
    BizCommerceViolationViolentContent,
    BizCommerceViolationWeapons,
    BizQuality,
    Default,
    WebCompanionOnly,
    Unknown(String),
}

impl ReachoutTimelockEnforcementType {
    #[must_use]
    pub fn from_wire(value: &str) -> Self {
        match value {
            "BIZ_COMMERCE_VIOLATION_ALCOHOL" => Self::BizCommerceViolationAlcohol,
            "BIZ_COMMERCE_VIOLATION_ADULT" => Self::BizCommerceViolationAdult,
            "BIZ_COMMERCE_VIOLATION_ANIMALS" => Self::BizCommerceViolationAnimals,
            "BIZ_COMMERCE_VIOLATION_BODY_PARTS_FLUIDS" => Self::BizCommerceViolationBodyPartsFluids,
            "BIZ_COMMERCE_VIOLATION_DATING" => Self::BizCommerceViolationDating,
            "BIZ_COMMERCE_VIOLATION_DIGITAL_SERVICES_PRODUCTS" => {
                Self::BizCommerceViolationDigitalServicesProducts
            }
            "BIZ_COMMERCE_VIOLATION_DRUGS" => Self::BizCommerceViolationDrugs,
            "BIZ_COMMERCE_VIOLATION_DRUGS_ONLY_OTC" => Self::BizCommerceViolationDrugsOnlyOtc,
            "BIZ_COMMERCE_VIOLATION_GAMBLING" => Self::BizCommerceViolationGambling,
            "BIZ_COMMERCE_VIOLATION_HEALTHCARE" => Self::BizCommerceViolationHealthcare,
            "BIZ_COMMERCE_VIOLATION_REAL_FAKE_CURRENCY" => {
                Self::BizCommerceViolationRealFakeCurrency
            }
            "BIZ_COMMERCE_VIOLATION_SUPPLEMENTS" => Self::BizCommerceViolationSupplements,
            "BIZ_COMMERCE_VIOLATION_TOBACCO" => Self::BizCommerceViolationTobacco,
            "BIZ_COMMERCE_VIOLATION_VIOLENT_CONTENT" => Self::BizCommerceViolationViolentContent,
            "BIZ_COMMERCE_VIOLATION_WEAPONS" => Self::BizCommerceViolationWeapons,
            "BIZ_QUALITY" => Self::BizQuality,
            "DEFAULT" => Self::Default,
            "WEB_COMPANION_ONLY" => Self::WebCompanionOnly,
            value => Self::Unknown(value.to_owned()),
        }
    }

    #[must_use]
    pub fn as_wire_str(&self) -> &str {
        match self {
            Self::BizCommerceViolationAlcohol => "BIZ_COMMERCE_VIOLATION_ALCOHOL",
            Self::BizCommerceViolationAdult => "BIZ_COMMERCE_VIOLATION_ADULT",
            Self::BizCommerceViolationAnimals => "BIZ_COMMERCE_VIOLATION_ANIMALS",
            Self::BizCommerceViolationBodyPartsFluids => "BIZ_COMMERCE_VIOLATION_BODY_PARTS_FLUIDS",
            Self::BizCommerceViolationDating => "BIZ_COMMERCE_VIOLATION_DATING",
            Self::BizCommerceViolationDigitalServicesProducts => {
                "BIZ_COMMERCE_VIOLATION_DIGITAL_SERVICES_PRODUCTS"
            }
            Self::BizCommerceViolationDrugs => "BIZ_COMMERCE_VIOLATION_DRUGS",
            Self::BizCommerceViolationDrugsOnlyOtc => "BIZ_COMMERCE_VIOLATION_DRUGS_ONLY_OTC",
            Self::BizCommerceViolationGambling => "BIZ_COMMERCE_VIOLATION_GAMBLING",
            Self::BizCommerceViolationHealthcare => "BIZ_COMMERCE_VIOLATION_HEALTHCARE",
            Self::BizCommerceViolationRealFakeCurrency => {
                "BIZ_COMMERCE_VIOLATION_REAL_FAKE_CURRENCY"
            }
            Self::BizCommerceViolationSupplements => "BIZ_COMMERCE_VIOLATION_SUPPLEMENTS",
            Self::BizCommerceViolationTobacco => "BIZ_COMMERCE_VIOLATION_TOBACCO",
            Self::BizCommerceViolationViolentContent => "BIZ_COMMERCE_VIOLATION_VIOLENT_CONTENT",
            Self::BizCommerceViolationWeapons => "BIZ_COMMERCE_VIOLATION_WEAPONS",
            Self::BizQuality => "BIZ_QUALITY",
            Self::Default => "DEFAULT",
            Self::WebCompanionOnly => "WEB_COMPANION_ONLY",
            Self::Unknown(value) => value,
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct MessageCappingInfo {
    pub total_quota: Option<u64>,
    pub used_quota: Option<u64>,
    pub cycle_start_timestamp: Option<u64>,
    pub cycle_end_timestamp: Option<u64>,
    pub server_sent_timestamp: Option<u64>,
    pub one_time_extension_status: Option<MessageCappingOneTimeExtensionStatus>,
    pub multi_variation_status: Option<MessageCappingMultiVariationStatus>,
    pub capping_status: Option<MessageCappingStatus>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MessageCappingStatus {
    None,
    FirstWarning,
    SecondWarning,
    Capped,
    Unknown(String),
}

impl MessageCappingStatus {
    #[must_use]
    pub fn from_wire(value: &str) -> Self {
        match value {
            "NONE" => Self::None,
            "FIRST_WARNING" => Self::FirstWarning,
            "SECOND_WARNING" => Self::SecondWarning,
            "CAPPED" => Self::Capped,
            value => Self::Unknown(value.to_owned()),
        }
    }

    #[must_use]
    pub fn as_wire_str(&self) -> &str {
        match self {
            Self::None => "NONE",
            Self::FirstWarning => "FIRST_WARNING",
            Self::SecondWarning => "SECOND_WARNING",
            Self::Capped => "CAPPED",
            Self::Unknown(value) => value,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MessageCappingMultiVariationStatus {
    NotEligible,
    NotActive,
    Active,
    ActiveUpgradeAvailable,
    Unknown(String),
}

impl MessageCappingMultiVariationStatus {
    #[must_use]
    pub fn from_wire(value: &str) -> Self {
        match value {
            "NOT_ELIGIBLE" => Self::NotEligible,
            "NOT_ACTIVE" => Self::NotActive,
            "ACTIVE" => Self::Active,
            "ACTIVE_UPGRADE_AVAILABLE" => Self::ActiveUpgradeAvailable,
            value => Self::Unknown(value.to_owned()),
        }
    }

    #[must_use]
    pub fn as_wire_str(&self) -> &str {
        match self {
            Self::NotEligible => "NOT_ELIGIBLE",
            Self::NotActive => "NOT_ACTIVE",
            Self::Active => "ACTIVE",
            Self::ActiveUpgradeAvailable => "ACTIVE_UPGRADE_AVAILABLE",
            Self::Unknown(value) => value,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MessageCappingOneTimeExtensionStatus {
    NotEligible,
    Eligible,
    ActiveInCurrentCycle,
    Exhausted,
    Unknown(String),
}

impl MessageCappingOneTimeExtensionStatus {
    #[must_use]
    pub fn from_wire(value: &str) -> Self {
        match value {
            "NOT_ELIGIBLE" => Self::NotEligible,
            "ELIGIBLE" => Self::Eligible,
            "ACTIVE_IN_CURRENT_CYCLE" => Self::ActiveInCurrentCycle,
            "EXHAUSTED" => Self::Exhausted,
            value => Self::Unknown(value.to_owned()),
        }
    }

    #[must_use]
    pub fn as_wire_str(&self) -> &str {
        match self {
            Self::NotEligible => "NOT_ELIGIBLE",
            Self::Eligible => "ELIGIBLE",
            Self::ActiveInCurrentCycle => "ACTIVE_IN_CURRENT_CYCLE",
            Self::Exhausted => "EXHAUSTED",
            Self::Unknown(value) => value,
        }
    }
}

pub fn build_account_reachout_timelock_query(tag: impl Into<String>) -> CoreResult<BinaryNode> {
    build_wmex_query(json!({}), QUERY_REACHOUT_TIMELOCK, tag)
}

pub fn build_message_capping_info_query(tag: impl Into<String>) -> CoreResult<BinaryNode> {
    build_wmex_query(
        json!({
            "input": {
                "type": "INDIVIDUAL_NEW_CHAT_MSG"
            }
        }),
        QUERY_MESSAGE_CAPPING_INFO,
        tag,
    )
}

pub fn parse_account_reachout_timelock_result(
    node: &BinaryNode,
) -> CoreResult<ReachoutTimelockState> {
    let value = parse_wmex_response(node, PATH_REACHOUT_TIMELOCK)?;
    Ok(parse_reachout_timelock_value(&value, None))
}

pub fn parse_message_capping_info_result(node: &BinaryNode) -> CoreResult<MessageCappingInfo> {
    let value = parse_wmex_response(node, PATH_MESSAGE_CAPPING_INFO)?;
    Ok(parse_message_capping_info_value(&value))
}

pub fn parse_account_update_notification(
    node: &BinaryNode,
    now_seconds: u64,
) -> CoreResult<Option<AccountUpdate>> {
    let Some(update) = child_node(node, "update") else {
        return Ok(None);
    };
    let Some(op_name) = update
        .attrs
        .get("op_name")
        .filter(|value| !value.trim().is_empty())
    else {
        return Ok(None);
    };

    let expected_path = match op_name.as_str() {
        OP_REACHOUT_TIMELOCK_UPDATE => PATH_NOTIFY_REACHOUT_TIMELOCK,
        OP_MESSAGE_CAPPING_INFO_UPDATE => PATH_NOTIFY_MESSAGE_CAPPING_INFO,
        _ => return Ok(None),
    };
    let json = notification_json(update)?;
    let data = json
        .get("data")
        .ok_or_else(|| CoreError::Protocol("WMex notification missing data object".to_owned()))?;
    let payload = data.get(expected_path).ok_or_else(|| {
        CoreError::Protocol(format!(
            "WMex notification missing data path: {expected_path}"
        ))
    })?;

    match op_name.as_str() {
        OP_REACHOUT_TIMELOCK_UPDATE => Ok(Some(AccountUpdate::ReachoutTimelock(
            parse_reachout_timelock_value(payload, Some(now_seconds)),
        ))),
        OP_MESSAGE_CAPPING_INFO_UPDATE => Ok(Some(AccountUpdate::MessageCapping(
            parse_message_capping_info_value(payload),
        ))),
        _ => Ok(None),
    }
}

fn notification_json(node: &BinaryNode) -> CoreResult<Value> {
    let bytes = node_bytes(node, "WMex notification update")?;
    if bytes.len() > DEFAULT_MAX_WMEX_JSON_BYTES {
        return Err(CoreError::Payload(format!(
            "WMex notification exceeds configured JSON limit: {} bytes exceeds {DEFAULT_MAX_WMEX_JSON_BYTES}",
            bytes.len()
        )));
    }
    let value: Value = serde_json::from_slice(bytes)
        .map_err(|err| CoreError::Protocol(format!("invalid WMex notification JSON: {err}")))?;
    if let Some(errors) = value.get("errors").and_then(Value::as_array)
        && !errors.is_empty()
    {
        return Err(CoreError::Protocol(
            "WMex notification includes errors".to_owned(),
        ));
    }
    Ok(value)
}

fn parse_reachout_timelock_value(
    value: &Value,
    notification_now_seconds: Option<u64>,
) -> ReachoutTimelockState {
    let is_active = bool_field(value, "is_active").unwrap_or(false);
    if !is_active {
        return ReachoutTimelockState::default();
    }

    let time_enforcement_ends = u64_field(value, "time_enforcement_ends")
        .filter(|value| *value != 0)
        .or_else(|| {
            notification_now_seconds
                .and_then(|now| now.checked_add(DEFAULT_REACHOUT_NOTIFICATION_SECONDS))
        });
    let enforcement_type = string_field(value, "enforcement_type")
        .map(|value| ReachoutTimelockEnforcementType::from_wire(&value))
        .unwrap_or(ReachoutTimelockEnforcementType::Default);

    ReachoutTimelockState {
        is_active,
        time_enforcement_ends,
        enforcement_type,
    }
}

fn parse_message_capping_info_value(value: &Value) -> MessageCappingInfo {
    MessageCappingInfo {
        total_quota: u64_field(value, "total_quota"),
        used_quota: u64_field(value, "used_quota"),
        cycle_start_timestamp: u64_field(value, "cycle_start_timestamp"),
        cycle_end_timestamp: u64_field(value, "cycle_end_timestamp"),
        server_sent_timestamp: u64_field(value, "server_sent_timestamp"),
        one_time_extension_status: string_field(value, "ote_status")
            .map(|value| MessageCappingOneTimeExtensionStatus::from_wire(&value)),
        multi_variation_status: string_field(value, "mv_status")
            .map(|value| MessageCappingMultiVariationStatus::from_wire(&value)),
        capping_status: string_field(value, "capping_status")
            .map(|value| MessageCappingStatus::from_wire(&value)),
    }
}

fn bool_field(value: &Value, key: &str) -> Option<bool> {
    match value.get(key)? {
        Value::Bool(value) => Some(*value),
        Value::String(value) => match value.as_str() {
            "true" => Some(true),
            "false" => Some(false),
            _ => None,
        },
        _ => None,
    }
}

fn string_field(value: &Value, key: &str) -> Option<String> {
    value.get(key).and_then(Value::as_str).map(str::to_owned)
}

fn u64_field(value: &Value, key: &str) -> Option<u64> {
    match value.get(key)? {
        Value::Number(number) => number.as_u64(),
        Value::String(value) => value.parse().ok(),
        _ => None,
    }
}

fn child_nodes(node: &BinaryNode) -> &[BinaryNode] {
    match &node.content {
        Some(BinaryNodeContent::Nodes(children)) => children,
        _ => &[],
    }
}

fn child_node<'a>(node: &'a BinaryNode, tag: &str) -> Option<&'a BinaryNode> {
    child_nodes(node).iter().find(|child| child.tag == tag)
}

fn node_bytes<'a>(node: &'a BinaryNode, label: &str) -> CoreResult<&'a [u8]> {
    match node.content.as_ref() {
        Some(BinaryNodeContent::Bytes(bytes)) => Ok(bytes.as_ref()),
        Some(BinaryNodeContent::Text(text)) => Ok(text.as_bytes()),
        Some(BinaryNodeContent::Nodes(_)) => Err(CoreError::Protocol(format!(
            "{label} content must be JSON bytes or text"
        ))),
        None => Err(CoreError::Protocol(format!("{label} content is missing"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[test]
    fn builds_account_wmex_queries() {
        let reachout = build_account_reachout_timelock_query("q-1").unwrap();
        assert_eq!(reachout.attrs["xmlns"], "w:mex");
        assert_eq!(reachout.attrs["to"], "s.whatsapp.net");
        let (query_id, variables) = wmex_query_parts(&reachout);
        assert_eq!(query_id, QUERY_REACHOUT_TIMELOCK);
        assert_eq!(variables, json!({}));

        let capping = build_message_capping_info_query("q-2").unwrap();
        let (query_id, variables) = wmex_query_parts(&capping);
        assert_eq!(query_id, QUERY_MESSAGE_CAPPING_INFO);
        assert_eq!(variables["input"]["type"], "INDIVIDUAL_NEW_CHAT_MSG");
    }

    #[test]
    fn parses_account_wmex_results() {
        let reachout = wmex_response(
            PATH_REACHOUT_TIMELOCK,
            r#"{
                "is_active": true,
                "time_enforcement_ends": "1700000000",
                "enforcement_type": "WEB_COMPANION_ONLY"
            }"#,
        );
        let reachout = parse_account_reachout_timelock_result(&reachout).unwrap();
        assert!(reachout.is_active);
        assert_eq!(reachout.time_enforcement_ends, Some(1_700_000_000));
        assert_eq!(
            reachout.enforcement_type,
            ReachoutTimelockEnforcementType::WebCompanionOnly
        );

        let capping = wmex_response(
            PATH_MESSAGE_CAPPING_INFO,
            r#"{
                "total_quota": 100,
                "used_quota": "7",
                "cycle_start_timestamp": "170",
                "cycle_end_timestamp": "180",
                "server_sent_timestamp": "175",
                "ote_status": "ELIGIBLE",
                "mv_status": "ACTIVE",
                "capping_status": "FIRST_WARNING"
            }"#,
        );
        let capping = parse_message_capping_info_result(&capping).unwrap();
        assert_eq!(capping.total_quota, Some(100));
        assert_eq!(capping.used_quota, Some(7));
        assert_eq!(
            capping.one_time_extension_status,
            Some(MessageCappingOneTimeExtensionStatus::Eligible)
        );
        assert_eq!(
            capping.multi_variation_status,
            Some(MessageCappingMultiVariationStatus::Active)
        );
        assert_eq!(
            capping.capping_status,
            Some(MessageCappingStatus::FirstWarning)
        );

        let attr_error = BinaryNode::new("iq")
            .with_attr("type", "error")
            .with_attr("code", "429")
            .with_attr("text", "rate limited");
        let err = parse_account_reachout_timelock_result(&attr_error).unwrap_err();
        assert!(
            err.to_string()
                .contains("WMex query failed (429): rate limited")
        );

        let child_error = BinaryNode::new("iq")
            .with_attr("type", "result")
            .with_content(vec![
                BinaryNode::new("error")
                    .with_attr("code", "503")
                    .with_attr("text", "try later"),
            ]);
        let err = parse_message_capping_info_result(&child_error).unwrap_err();
        assert!(
            err.to_string()
                .contains("WMex query failed (503): try later")
        );
    }

    #[test]
    fn parses_account_update_notifications() {
        let reachout = notification_update(
            OP_REACHOUT_TIMELOCK_UPDATE,
            PATH_NOTIFY_REACHOUT_TIMELOCK,
            r#"{
                "is_active": true,
                "enforcement_type": "BIZ_QUALITY"
            }"#,
        );
        assert_eq!(
            parse_account_update_notification(&reachout, 1_000).unwrap(),
            Some(AccountUpdate::ReachoutTimelock(ReachoutTimelockState {
                is_active: true,
                time_enforcement_ends: Some(1_060),
                enforcement_type: ReachoutTimelockEnforcementType::BizQuality
            }))
        );

        let lifted = notification_update(
            OP_REACHOUT_TIMELOCK_UPDATE,
            PATH_NOTIFY_REACHOUT_TIMELOCK,
            r#"{ "is_active": false }"#,
        );
        assert_eq!(
            parse_account_update_notification(&lifted, 1_000).unwrap(),
            Some(AccountUpdate::ReachoutTimelock(
                ReachoutTimelockState::default()
            ))
        );

        let capping = notification_update(
            OP_MESSAGE_CAPPING_INFO_UPDATE,
            PATH_NOTIFY_MESSAGE_CAPPING_INFO,
            r#"{
                "total_quota": "20",
                "used_quota": "19",
                "capping_status": "CAPPED"
            }"#,
        );
        assert_eq!(
            parse_account_update_notification(&capping, 1_000).unwrap(),
            Some(AccountUpdate::MessageCapping(MessageCappingInfo {
                total_quota: Some(20),
                used_quota: Some(19),
                capping_status: Some(MessageCappingStatus::Capped),
                ..MessageCappingInfo::default()
            }))
        );

        let unknown = BinaryNode::new("notification").with_content(vec![
            BinaryNode::new("update")
                .with_attr("op_name", "Other")
                .with_content(r#"{"data":{}}"#),
        ]);
        assert!(
            parse_account_update_notification(&unknown, 1_000)
                .unwrap()
                .is_none()
        );
    }

    fn wmex_query_parts(node: &BinaryNode) -> (&str, Value) {
        let query = child_node(node, "query").unwrap();
        let bytes = node_bytes(query, "query").unwrap();
        let value: Value = serde_json::from_slice(bytes).unwrap();
        (query.attrs["query_id"].as_str(), value["variables"].clone())
    }

    fn wmex_response(path: &str, payload: &str) -> BinaryNode {
        BinaryNode::new("iq")
            .with_content(vec![BinaryNode::new("result").with_content(
                format!(r#"{{"data":{{"{path}":{payload}}}}}"#).into_bytes(),
            )])
    }

    fn notification_update(op_name: &str, path: &str, payload: &str) -> BinaryNode {
        BinaryNode::new("notification").with_content(vec![
            BinaryNode::new("update")
                .with_attr("op_name", op_name)
                .with_content(format!(r#"{{"data":{{"{path}":{payload}}}}}"#).into_bytes()),
        ])
    }
}
