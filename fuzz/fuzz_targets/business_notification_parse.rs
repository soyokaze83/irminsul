#![no_main]

use libfuzzer_sys::fuzz_target;
use wa_binary::{BinaryNode, decode_binary_node};
use wa_core::{
    business_notification_events_from_notification_node, event_batch_from_notification_node,
    parse_inbound_notification,
};

const MAX_INPUT_LEN: usize = 64 * 1024;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_LEN {
        return;
    }

    if let Ok(node) = decode_binary_node(data) {
        drive_business_notification_parsers(&node);
    }

    let node = structured_business_notification(data);
    drive_business_notification_parsers(&node);
});

fn drive_business_notification_parsers(node: &BinaryNode) {
    let Ok(notification) = parse_inbound_notification(node) else {
        return;
    };
    let _ = business_notification_events_from_notification_node(node, &notification);
    let _ = event_batch_from_notification_node(node, &notification);
}

fn structured_business_notification(data: &[u8]) -> BinaryNode {
    let case = data.first().copied().unwrap_or_default() % 12;
    let actor = fuzz_account_jid(data.get(1).copied().unwrap_or_default());
    let business = fuzz_account_jid(data.get(2).copied().unwrap_or_default());
    let product_id = fuzz_id("sku", data.get(3).copied().unwrap_or_default());
    let catalog_id = fuzz_id("cat", data.get(4).copied().unwrap_or_default());
    let order_id = fuzz_id("order", data.get(5).copied().unwrap_or_default());
    let text = fuzz_text(data);
    let count = fuzz_number(data.get(6).copied().unwrap_or_default());

    let children = match case {
        0 => vec![
            BinaryNode::new("business_profile")
                .with_attr("version", count.as_str())
                .with_content(vec![
                    BinaryNode::new("profile")
                        .with_attr("jid", business.as_str())
                        .with_content(vec![
                            BinaryNode::new("description").with_content(text.clone()),
                            BinaryNode::new("address").with_content(text.clone()),
                        ]),
                ]),
        ],
        1 => vec![
            BinaryNode::new("product_catalog")
                .with_attr("catalog_id", catalog_id.as_str())
                .with_content(vec![product_node(
                    &product_id,
                    &text,
                    data.get(7).copied().unwrap_or_default(),
                )]),
        ],
        2 => vec![
            BinaryNode::new("product_catalog_add").with_content(vec![product_node(
                &product_id,
                &text,
                data.get(7).copied().unwrap_or_default(),
            )]),
        ],
        3 => vec![
            BinaryNode::new("product_catalog_edit")
                .with_attr("catalog_id", catalog_id.as_str())
                .with_content(vec![product_node(
                    &product_id,
                    &text,
                    data.get(7).copied().unwrap_or_default(),
                )]),
        ],
        4 => vec![
            BinaryNode::new("product_catalog_delete")
                .with_attr("deleted_count", count.as_str())
                .with_content(vec![
                    BinaryNode::new("product").with_attr("id", product_id.as_str()),
                ]),
        ],
        5 => vec![BinaryNode::new("collections").with_content(vec![
            BinaryNode::new("collection")
                .with_attr("id", fuzz_id("collection", data.get(7).copied().unwrap_or_default()))
                .with_content(vec![product_node(
                    &product_id,
                    &text,
                    data.get(8).copied().unwrap_or_default(),
                )]),
        ])],
        6 => vec![
            BinaryNode::new("order")
                .with_attr("id", order_id.as_str())
                .with_attr("status", order_status(data))
                .with_content(vec![
                    BinaryNode::new("price")
                        .with_attr("currency", currency(data))
                        .with_content(count.clone()),
                    product_node(&product_id, &text, data.get(7).copied().unwrap_or_default()),
                ]),
        ],
        7 => vec![
            BinaryNode::new("order_update")
                .with_attr("id", order_id.as_str())
                .with_attr("status", order_status(data))
                .with_content(vec![BinaryNode::new("note").with_content(text.clone())]),
        ],
        8 => vec![
            BinaryNode::new("cover_photo")
                .with_attr(
                    "id",
                    fuzz_id("cover", data.get(7).copied().unwrap_or_default()),
                )
                .with_attr("url", fuzz_url(data))
                .with_content(vec![
                    BinaryNode::new("media")
                        .with_attr("direct_path", format!("/business/{product_id}"))
                        .with_content(data.iter().skip(8).take(16).copied().collect::<Vec<_>>()),
                ]),
        ],
        9 => vec![
            BinaryNode::new("product_catalog_update")
                .with_attr("catalog-id", catalog_id.as_str())
                .with_content(vec![product_node(
                    &product_id,
                    &text,
                    data.get(7).copied().unwrap_or_default(),
                )]),
        ],
        10 => vec![
            BinaryNode::new("collection_update")
                .with_attr(
                    "collection-id",
                    fuzz_id("collection", data.get(7).copied().unwrap_or_default()),
                )
                .with_content(vec![BinaryNode::new("collection").with_content(vec![
                    BinaryNode::new("id").with_content(fuzz_id(
                        "collection",
                        data.get(8).copied().unwrap_or_default(),
                    )),
                    BinaryNode::new("name").with_content(text.clone()),
                ])]),
        ],
        _ => vec![
            BinaryNode::new("cart_update")
                .with_attr(
                    "cart-id",
                    fuzz_id("cart", data.get(7).copied().unwrap_or_default()),
                )
                .with_content(vec![
                    BinaryNode::new("item")
                        .with_attr("sku", product_id.as_str())
                        .with_attr("quantity", count.as_str()),
                ]),
        ],
    };

    BinaryNode::new("notification")
        .with_attr("id", format!("business-{}", data.len()))
        .with_attr("from", "server@s.whatsapp.net")
        .with_attr("type", notification_type(data))
        .with_attr("participant", actor)
        .with_attr("t", fuzz_number(data.get(9).copied().unwrap_or_default()))
        .with_content(children)
}

fn product_node(id: &str, text: &str, byte: u8) -> BinaryNode {
    BinaryNode::new("product")
        .with_attr("id", id)
        .with_attr("retailer_id", fuzz_id("retailer", byte))
        .with_content(vec![
            BinaryNode::new("name").with_content(text.to_owned()),
            BinaryNode::new("description").with_content(text.to_owned()),
            BinaryNode::new("media").with_content(vec![
                BinaryNode::new("image")
                    .with_attr("url", fuzz_url(&[byte]))
                    .with_attr("id", fuzz_id("image", byte)),
            ]),
        ])
}

fn fuzz_account_jid(byte: u8) -> String {
    match byte % 5 {
        0 => format!("{}@s.whatsapp.net", 100 + u16::from(byte)),
        1 => format!("{}@c.us", 200 + u16::from(byte)),
        2 => format!("{}@lid", 300 + u16::from(byte)),
        3 => String::new(),
        _ => format!("not-a-jid-{byte}"),
    }
}

fn fuzz_id(prefix: &str, byte: u8) -> String {
    if byte.is_multiple_of(11) {
        String::new()
    } else {
        format!("{prefix}-{byte}")
    }
}

fn fuzz_text(data: &[u8]) -> String {
    let text = data
        .iter()
        .skip(10)
        .take(40)
        .filter_map(|byte| {
            let ch = char::from(*byte);
            (ch.is_ascii_alphanumeric() || ch == ' ').then_some(ch)
        })
        .collect::<String>();
    if text.trim().is_empty() {
        "Business update".to_owned()
    } else {
        text
    }
}

fn fuzz_number(byte: u8) -> String {
    if byte.is_multiple_of(7) {
        "not-a-number".to_owned()
    } else {
        u32::from(byte).saturating_mul(1000).to_string()
    }
}

fn fuzz_url(data: &[u8]) -> String {
    let suffix = data.first().copied().unwrap_or_default();
    if suffix.is_multiple_of(5) {
        String::new()
    } else {
        format!("https://media.test/business/{suffix}")
    }
}

fn notification_type(data: &[u8]) -> &'static str {
    match data.get(11).copied().unwrap_or_default() % 4 {
        0 => "business",
        1 => "server_sync",
        2 => "",
        _ => "catalog",
    }
}

fn order_status(data: &[u8]) -> &'static str {
    match data.get(12).copied().unwrap_or_default() % 4 {
        0 => "pending",
        1 => "processing",
        2 => "complete",
        _ => "",
    }
}

fn currency(data: &[u8]) -> &'static str {
    match data.get(13).copied().unwrap_or_default() % 4 {
        0 => "USD",
        1 => "BRL",
        2 => "IDR",
        _ => "",
    }
}
