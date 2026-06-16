#![forbid(unsafe_code)]

use wa_binary::BinaryNode;

#[must_use]
pub fn ping_node() -> BinaryNode {
    BinaryNode::new("iq").with_attr("type", "get")
}
