use bytes::Bytes;
use std::collections::BTreeMap;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BinaryNode {
    pub tag: String,
    pub attrs: BTreeMap<String, String>,
    pub content: Option<BinaryNodeContent>,
}

impl BinaryNode {
    #[must_use]
    pub fn new(tag: impl Into<String>) -> Self {
        Self {
            tag: tag.into(),
            attrs: BTreeMap::new(),
            content: None,
        }
    }

    #[must_use]
    pub fn with_attr(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.attrs.insert(key.into(), value.into());
        self
    }

    #[must_use]
    pub fn with_content(mut self, content: impl Into<BinaryNodeContent>) -> Self {
        self.content = Some(content.into());
        self
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BinaryNodeContent {
    Nodes(Vec<BinaryNode>),
    Text(String),
    Bytes(Bytes),
}

impl From<Vec<BinaryNode>> for BinaryNodeContent {
    fn from(value: Vec<BinaryNode>) -> Self {
        Self::Nodes(value)
    }
}

impl From<String> for BinaryNodeContent {
    fn from(value: String) -> Self {
        Self::Text(value)
    }
}

impl From<&str> for BinaryNodeContent {
    fn from(value: &str) -> Self {
        Self::Text(value.to_owned())
    }
}

impl From<Bytes> for BinaryNodeContent {
    fn from(value: Bytes) -> Self {
        Self::Bytes(value)
    }
}

impl From<Vec<u8>> for BinaryNodeContent {
    fn from(value: Vec<u8>) -> Self {
        Self::Bytes(Bytes::from(value))
    }
}
