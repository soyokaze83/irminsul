use crate::{CoreError, CoreResult};
use bytes::Bytes;
use serde_json::{Value, json};
use wa_binary::{BinaryNode, BinaryNodeContent};

pub const WMEX_XMLNS: &str = "w:mex";
pub const WMEX_SERVER: &str = "s.whatsapp.net";
pub const DEFAULT_MAX_WMEX_JSON_BYTES: usize = 1024 * 1024;

pub fn build_wmex_query(
    variables: Value,
    query_id: impl Into<String>,
    tag: impl Into<String>,
) -> CoreResult<BinaryNode> {
    let query_id = query_id.into();
    let query_id = validate_non_empty("WMex query id", &query_id)?.to_owned();
    let payload = serde_json::to_vec(&json!({ "variables": variables }))
        .map_err(|err| CoreError::Payload(format!("failed to encode WMex variables: {err}")))?;

    Ok(BinaryNode::new("iq")
        .with_attr("id", tag.into())
        .with_attr("type", "get")
        .with_attr("to", WMEX_SERVER)
        .with_attr("xmlns", WMEX_XMLNS)
        .with_content(vec![
            BinaryNode::new("query")
                .with_attr("query_id", query_id)
                .with_content(Bytes::from(payload)),
        ]))
}

pub fn parse_wmex_response(node: &BinaryNode, data_path: &str) -> CoreResult<Value> {
    parse_wmex_response_with_limit(node, data_path, DEFAULT_MAX_WMEX_JSON_BYTES)
}

pub fn parse_wmex_response_with_limit(
    node: &BinaryNode,
    data_path: &str,
    max_json_bytes: usize,
) -> CoreResult<Value> {
    if max_json_bytes == 0 {
        return Err(CoreError::Payload(
            "WMex JSON byte limit must be greater than zero".to_owned(),
        ));
    }

    if let Some(error) = wmex_stanza_error(node) {
        return Err(error);
    }

    let result = child_node(node, "result")
        .ok_or_else(|| CoreError::Protocol("WMex response missing result node".to_owned()))?;
    let bytes = node_bytes(result, "WMex result")?;
    if bytes.len() > max_json_bytes {
        return Err(CoreError::Payload(format!(
            "WMex result exceeds configured JSON limit: {} bytes exceeds {max_json_bytes}",
            bytes.len()
        )));
    }

    let value: Value = serde_json::from_slice(bytes)
        .map_err(|err| CoreError::Protocol(format!("invalid WMex JSON response: {err}")))?;
    if let Some(errors) = value.get("errors").and_then(Value::as_array)
        && !errors.is_empty()
    {
        return Err(CoreError::Protocol(wmex_error_message(errors)));
    }

    let data = value
        .get("data")
        .ok_or_else(|| CoreError::Protocol("WMex response missing data object".to_owned()))?;
    if data_path.is_empty() {
        return Ok(data.clone());
    }

    data.get(data_path)
        .cloned()
        .ok_or_else(|| CoreError::Protocol(format!("WMex response missing data path: {data_path}")))
}

fn wmex_stanza_error(node: &BinaryNode) -> Option<CoreError> {
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
        .unwrap_or("WMex query failed");
    Some(CoreError::Protocol(format!(
        "WMex query failed ({code}): {text}"
    )))
}

fn wmex_error_message(errors: &[Value]) -> String {
    let messages = errors
        .iter()
        .filter_map(|error| error.get("message").and_then(Value::as_str))
        .filter(|message| !message.trim().is_empty())
        .collect::<Vec<_>>();
    let code = errors
        .first()
        .and_then(|error| error.get("extensions"))
        .and_then(|extensions| extensions.get("error_code"))
        .and_then(Value::as_u64);

    match (code, messages.is_empty()) {
        (Some(code), false) => format!("WMex server error {code}: {}", messages.join(", ")),
        (Some(code), true) => format!("WMex server error {code}"),
        (None, false) => format!("WMex server error: {}", messages.join(", ")),
        (None, true) => "WMex server error".to_owned(),
    }
}

fn child_node<'a>(node: &'a BinaryNode, tag: &str) -> Option<&'a BinaryNode> {
    let Some(BinaryNodeContent::Nodes(children)) = &node.content else {
        return None;
    };
    children.iter().find(|child| child.tag == tag)
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

fn validate_non_empty<'a>(label: &str, value: &'a str) -> CoreResult<&'a str> {
    if value.trim().is_empty() {
        return Err(CoreError::Protocol(format!("{label} must not be empty")));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn builds_wmex_query_with_json_variables() {
        let query =
            build_wmex_query(json!({ "newsletter_id": "abc@newsletter" }), "123", "q-1").unwrap();

        assert_eq!(query.tag, "iq");
        assert_eq!(query.attrs["id"], "q-1");
        assert_eq!(query.attrs["type"], "get");
        assert_eq!(query.attrs["to"], WMEX_SERVER);
        assert_eq!(query.attrs["xmlns"], WMEX_XMLNS);

        let Some(BinaryNodeContent::Nodes(children)) = &query.content else {
            panic!("expected query child");
        };
        assert_eq!(children[0].tag, "query");
        assert_eq!(children[0].attrs["query_id"], "123");
        let bytes = node_bytes(&children[0], "query").unwrap();
        let value: Value = serde_json::from_slice(bytes).unwrap();
        assert_eq!(
            value,
            json!({ "variables": { "newsletter_id": "abc@newsletter" } })
        );
    }

    #[test]
    fn parses_wmex_result_and_server_errors() {
        let ok = BinaryNode::new("iq").with_content(vec![
            BinaryNode::new("result").with_content(br#"{"data":{"path":{"ok":true}}}"#.to_vec()),
        ]);
        assert_eq!(
            parse_wmex_response(&ok, "path").unwrap(),
            json!({ "ok": true })
        );

        let err = BinaryNode::new("iq").with_content(vec![BinaryNode::new("result").with_content(
            br#"{"errors":[{"message":"denied","extensions":{"error_code":403}}]}"#.to_vec(),
        )]);
        assert!(matches!(
            parse_wmex_response(&err, "path"),
            Err(CoreError::Protocol(message))
                if message == "WMex server error 403: denied"
        ));

        let attr_error = BinaryNode::new("iq")
            .with_attr("type", "error")
            .with_attr("code", "429")
            .with_attr("text", "rate limited");
        assert!(matches!(
            parse_wmex_response(&attr_error, "path"),
            Err(CoreError::Protocol(message))
                if message == "WMex query failed (429): rate limited"
        ));

        let child_error = BinaryNode::new("iq")
            .with_attr("type", "result")
            .with_content(vec![
                BinaryNode::new("error")
                    .with_attr("code", "503")
                    .with_attr("text", "try later"),
            ]);
        assert!(matches!(
            parse_wmex_response(&child_error, "path"),
            Err(CoreError::Protocol(message))
                if message == "WMex query failed (503): try later"
        ));
    }
}
