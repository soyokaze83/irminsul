use crate::{CoreResult, Event, EventHub, QueryManager};
use bytes::Bytes;
use wa_binary::{BinaryNode, decode_binary_node, encode_binary_node};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InboundBinaryNode {
    pub response_tag: Option<String>,
    pub node: BinaryNode,
}

impl InboundBinaryNode {
    #[must_use]
    pub fn from_node(node: BinaryNode) -> Self {
        let response_tag = response_tag(&node).map(ToOwned::to_owned);
        Self { response_tag, node }
    }

    pub fn encode(&self) -> CoreResult<Bytes> {
        Ok(encode_binary_node(&self.node)?)
    }
}

pub fn decode_inbound_binary_node(input: &[u8]) -> CoreResult<InboundBinaryNode> {
    Ok(InboundBinaryNode::from_node(decode_binary_node(input)?))
}

#[must_use]
pub fn response_tag(node: &BinaryNode) -> Option<&str> {
    node.attrs.get("id").map(String::as_str)
}

pub fn dispatch_binary_node(
    queries: &QueryManager,
    events: &EventHub,
    inbound: InboundBinaryNode,
) -> CoreResult<bool> {
    if let Some(tag) = inbound.response_tag.as_deref() {
        let payload = inbound.encode()?;
        if queries.resolve(tag, payload)? {
            return Ok(true);
        }
    }

    events.emit(Event::RawNode(inbound.node));
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn extracts_response_tag_from_node_id_attr() {
        let node = BinaryNode::new("iq").with_attr("id", "123");

        assert_eq!(response_tag(&node), Some("123"));
        assert_eq!(
            InboundBinaryNode::from_node(node).response_tag,
            Some("123".to_owned())
        );
    }

    #[test]
    fn decodes_inbound_binary_node_and_extracts_tag() {
        let node = BinaryNode::new("iq")
            .with_attr("id", "abc")
            .with_attr("type", "result");
        let encoded = encode_binary_node(&node).unwrap();
        let inbound = decode_inbound_binary_node(&encoded).unwrap();

        assert_eq!(inbound.response_tag.as_deref(), Some("abc"));
        assert_eq!(inbound.node, node);
    }

    #[tokio::test]
    async fn dispatch_resolves_matching_query_waiter() {
        let events = EventHub::new(4);
        let queries = QueryManager::new(Some(Duration::from_secs(5)));
        let waiter = queries.register("abc").unwrap();
        let node = BinaryNode::new("iq")
            .with_attr("id", "abc")
            .with_attr("type", "result");

        assert!(
            dispatch_binary_node(
                &queries,
                &events,
                InboundBinaryNode::from_node(node.clone())
            )
            .unwrap()
        );

        let resolved = waiter.wait().await.unwrap();
        assert_eq!(decode_binary_node(&resolved).unwrap(), node);
    }

    #[tokio::test]
    async fn dispatch_emits_unmatched_raw_node_event() {
        let events = EventHub::new(4);
        let mut event_rx = events.subscribe();
        let queries = QueryManager::new(Some(Duration::from_secs(5)));
        let node = BinaryNode::new("message").with_attr("id", "missing-waiter");

        assert!(
            !dispatch_binary_node(
                &queries,
                &events,
                InboundBinaryNode::from_node(node.clone())
            )
            .unwrap()
        );

        assert!(matches!(
            event_rx.recv().await.unwrap(),
            Event::RawNode(received) if received == node
        ));
    }

    #[test]
    fn malformed_binary_node_returns_error() {
        assert!(decode_inbound_binary_node(&[0, 248]).is_err());
    }
}
