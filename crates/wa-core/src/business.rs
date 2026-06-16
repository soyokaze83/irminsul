use crate::{
    CoreError, CoreResult,
    media::{UploadedMediaLocation, media_download_url},
    message::UploadedMedia,
};
use bytes::Bytes;
use wa_binary::{BinaryNode, BinaryNodeContent, JidServer, jid_decode, jid_normalized_user};

pub const DEFAULT_BUSINESS_CATALOG_LIMIT: u32 = 10;
pub const DEFAULT_BUSINESS_COLLECTION_LIMIT: u32 = 51;
pub const MAX_BUSINESS_CATALOG_LIMIT: u32 = 100;
pub const MAX_BUSINESS_COLLECTION_LIMIT: u32 = 100;
pub const BUSINESS_SERVER: &str = "s.whatsapp.net";

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BusinessProfile {
    pub jid: Option<String>,
    pub address: Option<String>,
    pub description: String,
    pub websites: Vec<String>,
    pub email: Option<String>,
    pub category: Option<String>,
    pub business_hours: Option<BusinessHours>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BusinessHours {
    pub timezone: Option<String>,
    pub config: Vec<BusinessHoursConfig>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BusinessHoursConfig {
    pub day_of_week: String,
    pub mode: String,
    pub open_time: Option<u32>,
    pub close_time: Option<u32>,
}

impl BusinessHoursConfig {
    pub fn new(day_of_week: impl Into<String>, mode: impl Into<String>) -> CoreResult<Self> {
        let day_of_week = day_of_week.into();
        let mode = mode.into();
        let day_of_week = validate_non_empty("business hours day", &day_of_week)?.to_owned();
        let mode = validate_non_empty("business hours mode", &mode)?.to_owned();
        Ok(Self {
            day_of_week,
            mode,
            open_time: None,
            close_time: None,
        })
    }

    #[must_use]
    pub fn with_open_close(mut self, open_time: u32, close_time: u32) -> Self {
        self.open_time = Some(open_time);
        self.close_time = Some(close_time);
        self
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BusinessProfileUpdate {
    pub address: Option<String>,
    pub websites: Option<Vec<String>>,
    pub email: Option<String>,
    pub description: Option<String>,
    pub hours: Option<BusinessHours>,
}

impl BusinessProfileUpdate {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_address(mut self, address: impl Into<String>) -> Self {
        self.address = Some(address.into());
        self
    }

    #[must_use]
    pub fn with_websites<I, T>(mut self, websites: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: Into<String>,
    {
        self.websites = Some(websites.into_iter().map(Into::into).collect());
        self
    }

    #[must_use]
    pub fn with_email(mut self, email: impl Into<String>) -> Self {
        self.email = Some(email.into());
        self
    }

    #[must_use]
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    #[must_use]
    pub fn with_hours(mut self, hours: BusinessHours) -> Self {
        self.hours = Some(hours);
        self
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.address.is_none()
            && self.websites.is_none()
            && self.email.is_none()
            && self.description.is_none()
            && self.hours.is_none()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BusinessCatalogQuery {
    pub jid: String,
    pub limit: u32,
    pub cursor: Option<String>,
}

impl BusinessCatalogQuery {
    pub fn new(jid: &str) -> CoreResult<Self> {
        Ok(Self {
            jid: normalize_account_jid(jid)?,
            limit: DEFAULT_BUSINESS_CATALOG_LIMIT,
            cursor: None,
        })
    }

    pub fn with_limit(mut self, limit: u32) -> CoreResult<Self> {
        if limit == 0 || limit > MAX_BUSINESS_CATALOG_LIMIT {
            return Err(CoreError::Payload(format!(
                "business catalog limit must be between 1 and {MAX_BUSINESS_CATALOG_LIMIT}"
            )));
        }
        self.limit = limit;
        Ok(self)
    }

    pub fn with_cursor(mut self, cursor: impl Into<String>) -> CoreResult<Self> {
        let cursor = cursor.into();
        self.cursor = Some(validate_non_empty("business catalog cursor", &cursor)?.to_owned());
        Ok(self)
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BusinessCatalog {
    pub products: Vec<BusinessProduct>,
    pub next_page_cursor: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BusinessCollectionsQuery {
    pub jid: String,
    pub collection_limit: u32,
    pub item_limit: u32,
}

impl BusinessCollectionsQuery {
    pub fn new(jid: &str) -> CoreResult<Self> {
        Ok(Self {
            jid: normalize_account_jid(jid)?,
            collection_limit: DEFAULT_BUSINESS_COLLECTION_LIMIT,
            item_limit: DEFAULT_BUSINESS_COLLECTION_LIMIT,
        })
    }

    pub fn with_collection_limit(mut self, limit: u32) -> CoreResult<Self> {
        validate_collection_limit(limit, "business collection limit")?;
        self.collection_limit = limit;
        Ok(self)
    }

    pub fn with_item_limit(mut self, limit: u32) -> CoreResult<Self> {
        validate_collection_limit(limit, "business collection item limit")?;
        self.item_limit = limit;
        Ok(self)
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BusinessCatalogCollection {
    pub id: String,
    pub name: String,
    pub products: Vec<BusinessProduct>,
    pub status: BusinessCatalogStatus,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BusinessCatalogStatus {
    pub status: Option<String>,
    pub can_appeal: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BusinessOrderDetails {
    pub price: BusinessOrderPrice,
    pub products: Vec<BusinessOrderProduct>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BusinessOrderPrice {
    pub total: i64,
    pub currency: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BusinessOrderProduct {
    pub id: String,
    pub name: String,
    pub image_url: String,
    pub price: i64,
    pub currency: String,
    pub quantity: u32,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BusinessProduct {
    pub id: String,
    pub name: String,
    pub retailer_id: Option<String>,
    pub url: Option<String>,
    pub description: String,
    pub price: i64,
    pub currency: String,
    pub image_urls: BusinessProductImageUrls,
    pub review_status: Option<String>,
    pub is_hidden: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BusinessProductImageUrls {
    pub requested: Option<String>,
    pub original: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BusinessProductImage {
    pub url: String,
}

impl BusinessProductImage {
    pub fn new(url: impl Into<String>) -> CoreResult<Self> {
        let url = url.into();
        Ok(Self {
            url: validate_non_empty("business product image URL", &url)?.to_owned(),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BusinessCoverPhoto {
    pub url: String,
}

impl BusinessCoverPhoto {
    pub fn new(url: impl Into<String>) -> CoreResult<Self> {
        let url = url.into();
        Ok(Self {
            url: validate_non_empty("business cover photo URL", &url)?.to_owned(),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BusinessCoverPhotoUpload {
    pub id: String,
    pub token: String,
    pub timestamp: i64,
}

impl BusinessCoverPhotoUpload {
    pub fn new(
        id: impl Into<String>,
        token: impl Into<String>,
        timestamp: i64,
    ) -> CoreResult<Self> {
        let id = id.into();
        let token = token.into();
        if timestamp < 0 {
            return Err(CoreError::Payload(
                "business cover photo timestamp must not be negative".to_owned(),
            ));
        }
        Ok(Self {
            id: validate_non_empty("business cover photo id", &id)?.to_owned(),
            token: validate_non_empty("business cover photo token", &token)?.to_owned(),
            timestamp,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BusinessProductOrigin {
    Exempt,
    CountryCode(String),
}

impl BusinessProductOrigin {
    pub fn country_code(code: impl Into<String>) -> CoreResult<Self> {
        let code = code.into();
        Ok(Self::CountryCode(
            validate_non_empty("business product origin country", &code)?.to_owned(),
        ))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BusinessProductCreate {
    pub name: String,
    pub description: String,
    pub price: i64,
    pub currency: String,
    pub retailer_id: Option<String>,
    pub url: Option<String>,
    pub images: Vec<BusinessProductImage>,
    pub origin: BusinessProductOrigin,
    pub is_hidden: bool,
}

impl BusinessProductCreate {
    pub fn new(
        name: impl Into<String>,
        description: impl Into<String>,
        price: i64,
        currency: impl Into<String>,
    ) -> CoreResult<Self> {
        let name = name.into();
        let description = description.into();
        let currency = currency.into();
        validate_non_negative_price(price)?;
        Ok(Self {
            name: validate_non_empty("business product name", &name)?.to_owned(),
            description: validate_non_empty("business product description", &description)?
                .to_owned(),
            price,
            currency: validate_non_empty("business product currency", &currency)?.to_owned(),
            retailer_id: None,
            url: None,
            images: Vec::new(),
            origin: BusinessProductOrigin::Exempt,
            is_hidden: false,
        })
    }

    #[must_use]
    pub fn with_retailer_id(mut self, retailer_id: impl Into<String>) -> Self {
        self.retailer_id = Some(retailer_id.into());
        self
    }

    #[must_use]
    pub fn with_url(mut self, url: impl Into<String>) -> Self {
        self.url = Some(url.into());
        self
    }

    #[must_use]
    pub fn with_images<I>(mut self, images: I) -> Self
    where
        I: IntoIterator<Item = BusinessProductImage>,
    {
        self.images = images.into_iter().collect();
        self
    }

    #[must_use]
    pub fn with_origin(mut self, origin: BusinessProductOrigin) -> Self {
        self.origin = origin;
        self
    }

    #[must_use]
    pub fn hidden(mut self, is_hidden: bool) -> Self {
        self.is_hidden = is_hidden;
        self
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BusinessProductUpdate {
    pub name: Option<String>,
    pub description: Option<String>,
    pub price: Option<i64>,
    pub currency: Option<String>,
    pub retailer_id: Option<String>,
    pub url: Option<String>,
    pub images: Option<Vec<BusinessProductImage>>,
    pub is_hidden: Option<bool>,
}

impl BusinessProductUpdate {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    #[must_use]
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    #[must_use]
    pub fn with_price(mut self, price: i64) -> Self {
        self.price = Some(price);
        self
    }

    #[must_use]
    pub fn with_currency(mut self, currency: impl Into<String>) -> Self {
        self.currency = Some(currency.into());
        self
    }

    #[must_use]
    pub fn with_retailer_id(mut self, retailer_id: impl Into<String>) -> Self {
        self.retailer_id = Some(retailer_id.into());
        self
    }

    #[must_use]
    pub fn with_url(mut self, url: impl Into<String>) -> Self {
        self.url = Some(url.into());
        self
    }

    #[must_use]
    pub fn with_images<I>(mut self, images: I) -> Self
    where
        I: IntoIterator<Item = BusinessProductImage>,
    {
        self.images = Some(images.into_iter().collect());
        self
    }

    #[must_use]
    pub fn hidden(mut self, is_hidden: bool) -> Self {
        self.is_hidden = Some(is_hidden);
        self
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.name.is_none()
            && self.description.is_none()
            && self.price.is_none()
            && self.currency.is_none()
            && self.retailer_id.is_none()
            && self.url.is_none()
            && self.images.as_ref().is_none_or(Vec::is_empty)
            && self.is_hidden.is_none()
    }
}

pub fn build_business_profile_query(jid: &str, tag: impl Into<String>) -> CoreResult<BinaryNode> {
    let jid = normalize_account_jid(jid)?;
    Ok(BinaryNode::new("iq")
        .with_attr("id", tag.into())
        .with_attr("to", BUSINESS_SERVER)
        .with_attr("xmlns", "w:biz")
        .with_attr("type", "get")
        .with_content(vec![
            BinaryNode::new("business_profile")
                .with_attr("v", "244")
                .with_content(vec![BinaryNode::new("profile").with_attr("jid", jid)]),
        ]))
}

pub fn build_business_profile_update_query(
    update: BusinessProfileUpdate,
    tag: impl Into<String>,
) -> CoreResult<BinaryNode> {
    if update.is_empty() {
        return Err(CoreError::Payload(
            "business profile update must include at least one field".to_owned(),
        ));
    }

    let mut children = Vec::new();
    if let Some(address) = update.address {
        children.push(text_node("address", address));
    }
    if let Some(email) = update.email {
        children.push(text_node("email", email));
    }
    if let Some(description) = update.description {
        children.push(text_node("description", description));
    }
    if let Some(websites) = update.websites {
        for website in websites {
            children.push(text_node("website", website));
        }
    }
    if let Some(hours) = update.hours {
        children.push(business_hours_node(hours)?);
    }

    Ok(BinaryNode::new("iq")
        .with_attr("id", tag.into())
        .with_attr("to", BUSINESS_SERVER)
        .with_attr("type", "set")
        .with_attr("xmlns", "w:biz")
        .with_content(vec![
            BinaryNode::new("business_profile")
                .with_attr("v", "3")
                .with_attr("mutation_type", "delta")
                .with_content(children),
        ]))
}

pub fn build_business_cover_photo_update_query(
    upload: BusinessCoverPhotoUpload,
    tag: impl Into<String>,
) -> CoreResult<BinaryNode> {
    business_cover_photo_mutation_query(
        tag,
        BinaryNode::new("cover_photo")
            .with_attr("id", upload.id)
            .with_attr("op", "update")
            .with_attr("token", upload.token)
            .with_attr("ts", upload.timestamp.to_string()),
    )
}

pub fn build_business_cover_photo_delete_query(
    id: &str,
    tag: impl Into<String>,
) -> CoreResult<BinaryNode> {
    let id = validate_non_empty("business cover photo id", id)?;
    business_cover_photo_mutation_query(
        tag,
        BinaryNode::new("cover_photo")
            .with_attr("id", id.to_owned())
            .with_attr("op", "delete"),
    )
}

pub fn build_business_catalog_query(
    query: BusinessCatalogQuery,
    tag: impl Into<String>,
) -> CoreResult<BinaryNode> {
    let mut params = vec![
        text_node("limit", query.limit.to_string()),
        text_node("width", "100"),
        text_node("height", "100"),
    ];
    if let Some(cursor) = query.cursor {
        params.push(text_node("after", cursor));
    }

    Ok(BinaryNode::new("iq")
        .with_attr("id", tag.into())
        .with_attr("to", BUSINESS_SERVER)
        .with_attr("type", "get")
        .with_attr("xmlns", "w:biz:catalog")
        .with_content(vec![
            BinaryNode::new("product_catalog")
                .with_attr("jid", query.jid)
                .with_attr("allow_shop_source", "true")
                .with_content(params),
        ]))
}

pub fn build_business_collections_query(
    query: BusinessCollectionsQuery,
    tag: impl Into<String>,
) -> CoreResult<BinaryNode> {
    validate_collection_limit(query.collection_limit, "business collection limit")?;
    validate_collection_limit(query.item_limit, "business collection item limit")?;
    Ok(BinaryNode::new("iq")
        .with_attr("id", tag.into())
        .with_attr("to", BUSINESS_SERVER)
        .with_attr("type", "get")
        .with_attr("xmlns", "w:biz:catalog")
        .with_attr("smax_id", "35")
        .with_content(vec![
            BinaryNode::new("collections")
                .with_attr("biz_jid", query.jid)
                .with_content(vec![
                    text_node("collection_limit", query.collection_limit.to_string()),
                    text_node("item_limit", query.item_limit.to_string()),
                    text_node("width", "100"),
                    text_node("height", "100"),
                ]),
        ]))
}

pub fn build_business_order_details_query(
    order_id: &str,
    token_base64: &str,
    tag: impl Into<String>,
) -> CoreResult<BinaryNode> {
    let order_id = validate_non_empty("business order id", order_id)?;
    let token_base64 = validate_non_empty("business order token", token_base64)?;
    Ok(BinaryNode::new("iq")
        .with_attr("id", tag.into())
        .with_attr("to", BUSINESS_SERVER)
        .with_attr("type", "get")
        .with_attr("xmlns", "fb:thrift_iq")
        .with_attr("smax_id", "5")
        .with_content(vec![
            BinaryNode::new("order")
                .with_attr("op", "get")
                .with_attr("id", order_id)
                .with_content(vec![
                    BinaryNode::new("image_dimensions")
                        .with_content(vec![text_node("width", "100"), text_node("height", "100")]),
                    text_node("token", token_base64),
                ]),
        ]))
}

pub fn build_business_product_create_query(
    create: BusinessProductCreate,
    tag: impl Into<String>,
) -> CoreResult<BinaryNode> {
    let product = product_create_node(create)?;
    Ok(product_catalog_mutation_query(
        tag,
        "product_catalog_add",
        vec![
            product,
            text_node("width", "100"),
            text_node("height", "100"),
        ],
    ))
}

pub fn build_business_product_update_query(
    product_id: &str,
    update: BusinessProductUpdate,
    tag: impl Into<String>,
) -> CoreResult<BinaryNode> {
    let product_id = validate_non_empty("business product id", product_id)?;
    if update.is_empty() {
        return Err(CoreError::Payload(
            "business product update must include at least one field".to_owned(),
        ));
    }
    let product = product_update_node(product_id, update)?;
    Ok(product_catalog_mutation_query(
        tag,
        "product_catalog_edit",
        vec![
            product,
            text_node("width", "100"),
            text_node("height", "100"),
        ],
    ))
}

pub fn build_business_product_delete_query<I, T>(
    product_ids: I,
    tag: impl Into<String>,
) -> CoreResult<BinaryNode>
where
    I: IntoIterator<Item = T>,
    T: AsRef<str>,
{
    let products = product_ids
        .into_iter()
        .map(|id| {
            Ok(BinaryNode::new("product").with_content(vec![text_node(
                "id",
                validate_non_empty("business product id", id.as_ref())?.to_owned(),
            )]))
        })
        .collect::<CoreResult<Vec<_>>>()?;
    if products.is_empty() {
        return Err(CoreError::Payload(
            "business product delete must include at least one product id".to_owned(),
        ));
    }
    Ok(product_catalog_mutation_query(
        tag,
        "product_catalog_delete",
        products,
    ))
}

pub fn parse_business_profile(node: &BinaryNode) -> CoreResult<Option<BusinessProfile>> {
    let Some(profile) =
        child_node(node, "business_profile").and_then(|node| child_node(node, "profile"))
    else {
        return Ok(None);
    };

    Ok(Some(BusinessProfile {
        jid: profile.attrs.get("jid").cloned(),
        address: child_text(profile, "address")?,
        description: child_text(profile, "description")?.unwrap_or_default(),
        websites: child_nodes(profile)
            .iter()
            .filter(|child| child.tag == "website")
            .filter_map(|child| node_text(child).ok().flatten())
            .collect(),
        email: child_text(profile, "email")?,
        category: child_node(profile, "categories")
            .and_then(|categories| child_node(categories, "category"))
            .map(node_text)
            .transpose()?
            .flatten(),
        business_hours: child_node(profile, "business_hours")
            .map(parse_business_hours)
            .transpose()?,
    }))
}

pub fn parse_business_mutation_result(node: &BinaryNode) -> CoreResult<()> {
    if node.tag != "iq" {
        return Err(CoreError::Protocol(format!(
            "business mutation response must be iq, got {}",
            node.tag
        )));
    }
    match node.attrs.get("type").map(String::as_str) {
        Some("result") => Ok(()),
        Some("error") => Err(CoreError::Protocol(format!(
            "business mutation failed{}",
            stanza_error_suffix(node)
        ))),
        Some(value) => Err(CoreError::Protocol(format!(
            "unexpected business mutation response type: {value}"
        ))),
        None => Err(CoreError::Protocol(
            "business mutation response missing type".to_owned(),
        )),
    }
}

pub fn parse_business_catalog(node: &BinaryNode) -> CoreResult<BusinessCatalog> {
    let catalog = child_node(node, "product_catalog").ok_or_else(|| {
        CoreError::Protocol("business catalog response missing product_catalog".to_owned())
    })?;
    let products = child_nodes(catalog)
        .iter()
        .filter(|child| child.tag == "product")
        .map(parse_business_product)
        .collect::<CoreResult<Vec<_>>>()?;
    let next_page_cursor = child_node(catalog, "paging")
        .and_then(|paging| child_text(paging, "after").transpose())
        .transpose()?;

    Ok(BusinessCatalog {
        products,
        next_page_cursor,
    })
}

pub fn parse_business_collections(node: &BinaryNode) -> CoreResult<Vec<BusinessCatalogCollection>> {
    let collections = child_node(node, "collections")
        .ok_or_else(|| CoreError::Protocol("business response missing collections".to_owned()))?;
    child_nodes(collections)
        .iter()
        .filter(|child| child.tag == "collection")
        .map(parse_business_collection)
        .collect()
}

pub fn parse_business_order_details(node: &BinaryNode) -> CoreResult<BusinessOrderDetails> {
    let order = child_node(node, "order")
        .ok_or_else(|| CoreError::Protocol("business response missing order".to_owned()))?;
    let price = child_node(order, "price")
        .ok_or_else(|| CoreError::Protocol("business order missing price".to_owned()))?;
    let products = child_nodes(order)
        .iter()
        .filter(|child| child.tag == "product")
        .map(parse_business_order_product)
        .collect::<CoreResult<Vec<_>>>()?;
    Ok(BusinessOrderDetails {
        price: BusinessOrderPrice {
            total: required_child_i64(price, "total")?,
            currency: required_child_text(price, "currency")?,
        },
        products,
    })
}

pub fn parse_business_product_create_result(node: &BinaryNode) -> CoreResult<BusinessProduct> {
    parse_product_mutation_result(node, "product_catalog_add")
}

pub fn parse_business_product_update_result(node: &BinaryNode) -> CoreResult<BusinessProduct> {
    parse_product_mutation_result(node, "product_catalog_edit")
}

pub fn parse_business_product_delete_result(node: &BinaryNode) -> CoreResult<u32> {
    let delete = child_node(node, "product_catalog_delete").ok_or_else(|| {
        CoreError::Protocol(
            "business product delete response missing product_catalog_delete".to_owned(),
        )
    })?;
    delete
        .attrs
        .get("deleted_count")
        .map(|value| {
            value.parse::<u32>().map_err(|err| {
                CoreError::Protocol(format!("invalid business product deleted_count: {err}"))
            })
        })
        .transpose()
        .map(|count| count.unwrap_or(0))
}

pub fn business_product_image_from_uploaded_media(
    media: &UploadedMedia,
    fallback_host: Option<&str>,
) -> CoreResult<BusinessProductImage> {
    BusinessProductImage::new(business_media_url_from_uploaded_media(
        media,
        fallback_host,
    )?)
}

pub fn business_cover_photo_from_uploaded_media(
    media: &UploadedMedia,
    fallback_host: Option<&str>,
) -> CoreResult<BusinessCoverPhoto> {
    BusinessCoverPhoto::new(business_media_url_from_uploaded_media(
        media,
        fallback_host,
    )?)
}

pub fn business_cover_photo_upload_from_location(
    location: &UploadedMediaLocation,
) -> CoreResult<BusinessCoverPhotoUpload> {
    BusinessCoverPhotoUpload::new(
        location.upload_id.as_deref().ok_or_else(|| {
            CoreError::Protocol("business cover photo upload missing id".to_owned())
        })?,
        location.upload_token.as_deref().ok_or_else(|| {
            CoreError::Protocol("business cover photo upload missing token".to_owned())
        })?,
        location.media_key_timestamp.ok_or_else(|| {
            CoreError::Protocol("business cover photo upload missing timestamp".to_owned())
        })?,
    )
}

fn parse_business_hours(node: &BinaryNode) -> CoreResult<BusinessHours> {
    let config = child_nodes(node)
        .iter()
        .filter(|child| child.tag == "business_hours_config")
        .map(|child| {
            Ok(BusinessHoursConfig {
                day_of_week: required_attr(child, "day_of_week")?.to_owned(),
                mode: required_attr(child, "mode")?.to_owned(),
                open_time: optional_u32_attr(child, "open_time")?,
                close_time: optional_u32_attr(child, "close_time")?,
            })
        })
        .collect::<CoreResult<Vec<_>>>()?;
    Ok(BusinessHours {
        timezone: node.attrs.get("timezone").cloned(),
        config,
    })
}

fn parse_business_product(node: &BinaryNode) -> CoreResult<BusinessProduct> {
    let media = child_node(node, "media");
    let image = media.and_then(|media| child_node(media, "image"));
    let status_info = child_node(node, "status_info");

    Ok(BusinessProduct {
        id: required_child_text(node, "id")?,
        name: required_child_text(node, "name")?,
        retailer_id: child_text(node, "retailer_id")?,
        url: child_text(node, "url")?,
        description: child_text(node, "description")?.unwrap_or_default(),
        price: required_child_i64(node, "price")?,
        currency: required_child_text(node, "currency")?,
        image_urls: BusinessProductImageUrls {
            requested: image
                .map(|image| {
                    child_text(image, "request_image_url")
                        .and_then(|value| Ok(value.or(child_text(image, "url")?)))
                })
                .transpose()?
                .flatten(),
            original: image
                .map(|image| child_text(image, "original_image_url"))
                .transpose()?
                .flatten(),
        },
        review_status: status_info
            .map(|status| child_text(status, "status"))
            .transpose()?
            .flatten(),
        is_hidden: node
            .attrs
            .get("is_hidden")
            .is_some_and(|value| value == "true"),
    })
}

fn parse_business_collection(node: &BinaryNode) -> CoreResult<BusinessCatalogCollection> {
    let products = child_nodes(node)
        .iter()
        .filter(|child| child.tag == "product")
        .map(parse_business_product)
        .collect::<CoreResult<Vec<_>>>()?;
    Ok(BusinessCatalogCollection {
        id: required_child_text(node, "id")?,
        name: required_child_text(node, "name")?,
        products,
        status: parse_catalog_status(node)?,
    })
}

fn parse_catalog_status(node: &BinaryNode) -> CoreResult<BusinessCatalogStatus> {
    let Some(status_info) = child_node(node, "status_info") else {
        return Ok(BusinessCatalogStatus::default());
    };
    Ok(BusinessCatalogStatus {
        status: child_text(status_info, "status")?,
        can_appeal: child_text(status_info, "can_appeal")?.is_some_and(|value| value == "true"),
    })
}

fn parse_business_order_product(node: &BinaryNode) -> CoreResult<BusinessOrderProduct> {
    let image = child_node(node, "image")
        .ok_or_else(|| CoreError::Protocol("business order product missing image".to_owned()))?;
    Ok(BusinessOrderProduct {
        id: required_child_text(node, "id")?,
        name: required_child_text(node, "name")?,
        image_url: required_child_text(image, "url")?,
        price: required_child_i64(node, "price")?,
        currency: required_child_text(node, "currency")?,
        quantity: required_child_u32(node, "quantity")?,
    })
}

fn parse_product_mutation_result(node: &BinaryNode, wrapper: &str) -> CoreResult<BusinessProduct> {
    let wrapper = child_node(node, wrapper)
        .ok_or_else(|| CoreError::Protocol(format!("business response missing {wrapper}")))?;
    let product = child_node(wrapper, "product").ok_or_else(|| {
        CoreError::Protocol("business product mutation response missing product".to_owned())
    })?;
    parse_business_product(product)
}

fn product_create_node(create: BusinessProductCreate) -> CoreResult<BinaryNode> {
    let mut product = BusinessProductUpdate::new()
        .with_name(create.name)
        .with_description(create.description)
        .with_price(create.price)
        .with_currency(create.currency)
        .with_images(create.images)
        .hidden(create.is_hidden);
    if let Some(retailer_id) = create.retailer_id {
        product = product.with_retailer_id(retailer_id);
    }
    if let Some(url) = create.url {
        product = product.with_url(url);
    }
    let mut node = product_update_node_without_id(product)?;
    node = match create.origin {
        BusinessProductOrigin::Exempt => {
            node.with_attr("compliance_category", "COUNTRY_ORIGIN_EXEMPT")
        }
        BusinessProductOrigin::CountryCode(code) => append_child(
            node,
            BinaryNode::new("compliance_info").with_content(vec![text_node(
                "country_code_origin",
                validate_non_empty("business product origin country", &code)?.to_owned(),
            )]),
        ),
    };
    Ok(node)
}

fn product_update_node(product_id: &str, update: BusinessProductUpdate) -> CoreResult<BinaryNode> {
    Ok(prepend_child(
        product_update_node_without_id(update)?,
        text_node("id", product_id.to_owned()),
    ))
}

fn product_update_node_without_id(update: BusinessProductUpdate) -> CoreResult<BinaryNode> {
    let mut node = BinaryNode::new("product");
    let mut children = Vec::new();
    if let Some(name) = update.name {
        children.push(text_node(
            "name",
            validate_non_empty("business product name", &name)?.to_owned(),
        ));
    }
    if let Some(description) = update.description {
        children.push(text_node(
            "description",
            validate_non_empty("business product description", &description)?.to_owned(),
        ));
    }
    if let Some(retailer_id) = update.retailer_id {
        children.push(text_node(
            "retailer_id",
            validate_non_empty("business product retailer id", &retailer_id)?.to_owned(),
        ));
    }
    if let Some(url) = update.url {
        children.push(text_node(
            "url",
            validate_non_empty("business product URL", &url)?.to_owned(),
        ));
    }
    if let Some(images) = update.images.filter(|images| !images.is_empty()) {
        children.push(
            BinaryNode::new("media").with_content(
                images
                    .into_iter()
                    .map(|image| {
                        Ok(BinaryNode::new("image").with_content(vec![text_node(
                            "url",
                            validate_non_empty("business product image URL", &image.url)
                                .map(str::to_owned)?,
                        )]))
                    })
                    .collect::<CoreResult<Vec<_>>>()?,
            ),
        );
    }
    if let Some(price) = update.price {
        validate_non_negative_price(price)?;
        children.push(text_node("price", price.to_string()));
    }
    if let Some(currency) = update.currency {
        children.push(text_node(
            "currency",
            validate_non_empty("business product currency", &currency)?.to_owned(),
        ));
    }
    if let Some(is_hidden) = update.is_hidden {
        node = node.with_attr("is_hidden", is_hidden.to_string());
    }
    Ok(node.with_content(children))
}

fn append_child(mut node: BinaryNode, child: BinaryNode) -> BinaryNode {
    let mut children = match node.content.take() {
        Some(BinaryNodeContent::Nodes(children)) => children,
        _ => Vec::new(),
    };
    children.push(child);
    node.content = Some(BinaryNodeContent::Nodes(children));
    node
}

fn prepend_child(mut node: BinaryNode, child: BinaryNode) -> BinaryNode {
    let mut children = match node.content.take() {
        Some(BinaryNodeContent::Nodes(children)) => children,
        _ => Vec::new(),
    };
    children.insert(0, child);
    node.content = Some(BinaryNodeContent::Nodes(children));
    node
}

fn product_catalog_mutation_query(
    tag: impl Into<String>,
    wrapper: &str,
    content: Vec<BinaryNode>,
) -> BinaryNode {
    BinaryNode::new("iq")
        .with_attr("id", tag.into())
        .with_attr("to", BUSINESS_SERVER)
        .with_attr("type", "set")
        .with_attr("xmlns", "w:biz:catalog")
        .with_content(vec![
            BinaryNode::new(wrapper)
                .with_attr("v", "1")
                .with_content(content),
        ])
}

fn business_media_url_from_uploaded_media(
    media: &UploadedMedia,
    fallback_host: Option<&str>,
) -> CoreResult<String> {
    media_download_url(
        media.direct_path.as_deref(),
        media.url.as_deref(),
        fallback_host,
    )
}

fn business_cover_photo_mutation_query(
    tag: impl Into<String>,
    cover_photo: BinaryNode,
) -> CoreResult<BinaryNode> {
    Ok(BinaryNode::new("iq")
        .with_attr("id", tag.into())
        .with_attr("to", BUSINESS_SERVER)
        .with_attr("type", "set")
        .with_attr("xmlns", "w:biz")
        .with_content(vec![
            BinaryNode::new("business_profile")
                .with_attr("v", "3")
                .with_attr("mutation_type", "delta")
                .with_content(vec![cover_photo]),
        ]))
}

fn stanza_error_suffix(node: &BinaryNode) -> String {
    let code = node.attrs.get("code").or_else(|| node.attrs.get("error"));
    let text = node.attrs.get("text").or_else(|| node.attrs.get("reason"));
    match (code, text) {
        (Some(code), Some(text)) if !code.is_empty() && !text.is_empty() => {
            format!(" with code {code}: {text}")
        }
        (Some(code), _) if !code.is_empty() => format!(" with code {code}"),
        (_, Some(text)) if !text.is_empty() => format!(": {text}"),
        _ => String::new(),
    }
}

fn business_hours_node(hours: BusinessHours) -> CoreResult<BinaryNode> {
    let mut node = BinaryNode::new("business_hours");
    if let Some(timezone) = hours.timezone {
        node = node.with_attr(
            "timezone",
            validate_non_empty("business hours timezone", &timezone)?,
        );
    }
    let children = hours
        .config
        .into_iter()
        .map(|config| {
            let mut node = BinaryNode::new("business_hours_config")
                .with_attr(
                    "day_of_week",
                    validate_non_empty("business hours day", &config.day_of_week)?,
                )
                .with_attr(
                    "mode",
                    validate_non_empty("business hours mode", &config.mode)?,
                );
            if let Some(open_time) = config.open_time {
                node = node.with_attr("open_time", open_time.to_string());
            }
            if let Some(close_time) = config.close_time {
                node = node.with_attr("close_time", close_time.to_string());
            }
            Ok(node)
        })
        .collect::<CoreResult<Vec<_>>>()?;
    Ok(node.with_content(children))
}

fn text_node(tag: impl Into<String>, value: impl Into<String>) -> BinaryNode {
    BinaryNode::new(tag).with_content(Bytes::from(value.into()))
}

fn normalize_account_jid(jid: &str) -> CoreResult<String> {
    let decoded = jid_decode(jid)
        .ok_or_else(|| CoreError::Protocol(format!("invalid business JID: {jid}")))?;
    if matches!(
        decoded.server,
        JidServer::GUs | JidServer::Broadcast | JidServer::Newsletter | JidServer::Call
    ) {
        return Err(CoreError::Protocol(format!(
            "business JID must be an account JID: {jid}"
        )));
    }
    Ok(jid_normalized_user(jid).unwrap_or_else(|| jid.to_owned()))
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

fn child_text(node: &BinaryNode, tag: &str) -> CoreResult<Option<String>> {
    child_node(node, tag)
        .map(node_text)
        .transpose()
        .map(Option::flatten)
}

fn required_child_text(node: &BinaryNode, tag: &str) -> CoreResult<String> {
    child_text(node, tag)?
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            CoreError::Protocol(format!("business node missing required child text: {tag}"))
        })
}

fn required_child_i64(node: &BinaryNode, tag: &str) -> CoreResult<i64> {
    let text = required_child_text(node, tag)?;
    text.parse::<i64>()
        .map_err(|err| CoreError::Protocol(format!("invalid business numeric child {tag}: {err}")))
}

fn required_child_u32(node: &BinaryNode, tag: &str) -> CoreResult<u32> {
    let text = required_child_text(node, tag)?;
    text.parse::<u32>()
        .map_err(|err| CoreError::Protocol(format!("invalid business numeric child {tag}: {err}")))
}

fn node_text(node: &BinaryNode) -> CoreResult<Option<String>> {
    match node.content.as_ref() {
        Some(BinaryNodeContent::Text(value)) => Ok(Some(value.clone())),
        Some(BinaryNodeContent::Bytes(value)) => String::from_utf8(value.to_vec())
            .map(Some)
            .map_err(|err| CoreError::Protocol(format!("invalid business node text: {err}"))),
        Some(BinaryNodeContent::Nodes(_)) | None => Ok(None),
    }
}

fn required_attr<'a>(node: &'a BinaryNode, attr: &str) -> CoreResult<&'a str> {
    node.attrs
        .get(attr)
        .map(String::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| CoreError::Protocol(format!("business node missing attr: {attr}")))
}

fn optional_u32_attr(node: &BinaryNode, attr: &str) -> CoreResult<Option<u32>> {
    node.attrs
        .get(attr)
        .map(|value| {
            value
                .parse::<u32>()
                .map_err(|err| CoreError::Protocol(format!("invalid business attr {attr}: {err}")))
        })
        .transpose()
}

fn validate_non_empty<'a>(label: &str, value: &'a str) -> CoreResult<&'a str> {
    if value.trim().is_empty() {
        return Err(CoreError::Protocol(format!("{label} must not be empty")));
    }
    Ok(value)
}

fn validate_non_negative_price(price: i64) -> CoreResult<()> {
    if price < 0 {
        return Err(CoreError::Payload(
            "business product price must not be negative".to_owned(),
        ));
    }
    Ok(())
}

fn validate_collection_limit(limit: u32, label: &str) -> CoreResult<()> {
    if limit == 0 || limit > MAX_BUSINESS_COLLECTION_LIMIT {
        return Err(CoreError::Payload(format!(
            "{label} must be between 1 and {MAX_BUSINESS_COLLECTION_LIMIT}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_profile_fetch_update_and_catalog_queries() {
        let profile = build_business_profile_query("123@c.us", "q-1").unwrap();
        assert_eq!(profile.attrs["xmlns"], "w:biz");
        assert_eq!(profile.attrs["type"], "get");
        assert_eq!(
            child_node(child_node(&profile, "business_profile").unwrap(), "profile")
                .unwrap()
                .attrs["jid"],
            "123@s.whatsapp.net"
        );

        let hours = BusinessHours {
            timezone: Some("UTC".to_owned()),
            config: vec![
                BusinessHoursConfig::new("mon", "specific_hours")
                    .unwrap()
                    .with_open_close(540, 1020),
            ],
        };
        let update = BusinessProfileUpdate::new()
            .with_address("1 Main")
            .with_email("shop@example.com")
            .with_description("Open")
            .with_websites(["https://example.com"])
            .with_hours(hours);
        let update = build_business_profile_update_query(update, "q-2").unwrap();
        assert_eq!(update.attrs["xmlns"], "w:biz");
        assert_eq!(update.attrs["type"], "set");
        let profile = child_node(&update, "business_profile").unwrap();
        assert_eq!(profile.attrs["mutation_type"], "delta");
        assert_eq!(
            child_text(profile, "address").unwrap().as_deref(),
            Some("1 Main")
        );
        assert_eq!(
            child_text(profile, "website").unwrap().as_deref(),
            Some("https://example.com")
        );
        let hours = child_node(profile, "business_hours").unwrap();
        assert_eq!(hours.attrs["timezone"], "UTC");
        let config = child_node(hours, "business_hours_config").unwrap();
        assert_eq!(config.attrs["day_of_week"], "mon");
        assert_eq!(config.attrs["mode"], "specific_hours");
        assert_eq!(config.attrs["open_time"], "540");

        let cover_update = build_business_cover_photo_update_query(
            BusinessCoverPhotoUpload::new("fbid-1", "token-1", 1_700_000_000).unwrap(),
            "q-cover-update",
        )
        .unwrap();
        assert_eq!(cover_update.attrs["xmlns"], "w:biz");
        assert_eq!(cover_update.attrs["type"], "set");
        let profile = child_node(&cover_update, "business_profile").unwrap();
        assert_eq!(profile.attrs["mutation_type"], "delta");
        let cover = child_node(profile, "cover_photo").unwrap();
        assert_eq!(cover.attrs["op"], "update");
        assert_eq!(cover.attrs["id"], "fbid-1");
        assert_eq!(cover.attrs["token"], "token-1");
        assert_eq!(cover.attrs["ts"], "1700000000");

        let cover_delete =
            build_business_cover_photo_delete_query("fbid-1", "q-cover-delete").unwrap();
        let profile = child_node(&cover_delete, "business_profile").unwrap();
        let cover = child_node(profile, "cover_photo").unwrap();
        assert_eq!(cover.attrs["op"], "delete");
        assert_eq!(cover.attrs["id"], "fbid-1");

        let catalog = BusinessCatalogQuery::new("123@s.whatsapp.net")
            .unwrap()
            .with_limit(25)
            .unwrap()
            .with_cursor("cursor")
            .unwrap();
        let catalog = build_business_catalog_query(catalog, "q-3").unwrap();
        assert_eq!(catalog.attrs["xmlns"], "w:biz:catalog");
        let product_catalog = child_node(&catalog, "product_catalog").unwrap();
        assert_eq!(product_catalog.attrs["jid"], "123@s.whatsapp.net");
        assert_eq!(
            child_text(product_catalog, "limit").unwrap().as_deref(),
            Some("25")
        );
        assert_eq!(
            child_text(product_catalog, "after").unwrap().as_deref(),
            Some("cursor")
        );

        let collections = BusinessCollectionsQuery::new("123@c.us")
            .unwrap()
            .with_collection_limit(25)
            .unwrap()
            .with_item_limit(10)
            .unwrap();
        let collections = build_business_collections_query(collections, "q-4").unwrap();
        assert_eq!(collections.attrs["xmlns"], "w:biz:catalog");
        assert_eq!(collections.attrs["smax_id"], "35");
        let collections_node = child_node(&collections, "collections").unwrap();
        assert_eq!(collections_node.attrs["biz_jid"], "123@s.whatsapp.net");
        assert_eq!(
            child_text(collections_node, "collection_limit")
                .unwrap()
                .as_deref(),
            Some("25")
        );
        assert_eq!(
            child_text(collections_node, "item_limit")
                .unwrap()
                .as_deref(),
            Some("10")
        );

        let order = build_business_order_details_query("order-1", "token", "q-5").unwrap();
        assert_eq!(order.attrs["xmlns"], "fb:thrift_iq");
        assert_eq!(order.attrs["smax_id"], "5");
        let order_node = child_node(&order, "order").unwrap();
        assert_eq!(order_node.attrs["op"], "get");
        assert_eq!(order_node.attrs["id"], "order-1");
        assert_eq!(
            child_text(order_node, "token").unwrap().as_deref(),
            Some("token")
        );
        let dimensions = child_node(order_node, "image_dimensions").unwrap();
        assert_eq!(
            child_text(dimensions, "width").unwrap().as_deref(),
            Some("100")
        );
    }

    #[test]
    fn parses_business_profile_and_catalog() {
        let response = BinaryNode::new("iq").with_content(vec![
            BinaryNode::new("business_profile").with_content(vec![
                BinaryNode::new("profile")
                    .with_attr("jid", "123@s.whatsapp.net")
                    .with_content(vec![
                        text_node("address", "1 Main"),
                        text_node("description", "Daily goods"),
                        text_node("website", "https://example.com"),
                        text_node("email", "shop@example.com"),
                        BinaryNode::new("categories")
                            .with_content(vec![text_node("category", "Grocery")]),
                        BinaryNode::new("business_hours")
                            .with_attr("timezone", "UTC")
                            .with_content(vec![
                                BinaryNode::new("business_hours_config")
                                    .with_attr("day_of_week", "mon")
                                    .with_attr("mode", "specific_hours")
                                    .with_attr("open_time", "540")
                                    .with_attr("close_time", "1020"),
                            ]),
                    ]),
            ]),
        ]);
        let profile = parse_business_profile(&response).unwrap().unwrap();
        assert_eq!(profile.jid.as_deref(), Some("123@s.whatsapp.net"));
        assert_eq!(profile.description, "Daily goods");
        assert_eq!(profile.websites, vec!["https://example.com"]);
        assert_eq!(profile.category.as_deref(), Some("Grocery"));
        let hours = profile.business_hours.unwrap();
        assert_eq!(hours.timezone.as_deref(), Some("UTC"));
        assert_eq!(hours.config[0].open_time, Some(540));

        let catalog = BinaryNode::new("iq").with_content(vec![
            BinaryNode::new("product_catalog").with_content(vec![
                BinaryNode::new("product")
                    .with_attr("is_hidden", "true")
                    .with_content(vec![
                        text_node("id", "sku-1"),
                        text_node("name", "Widget"),
                        text_node("retailer_id", "retailer"),
                        text_node("description", "Useful"),
                        text_node("price", "12345000"),
                        text_node("currency", "USD"),
                        BinaryNode::new("media").with_content(vec![
                            BinaryNode::new("image").with_content(vec![
                                text_node("request_image_url", "https://img/small"),
                                text_node("original_image_url", "https://img/full"),
                            ]),
                        ]),
                        BinaryNode::new("status_info")
                            .with_content(vec![text_node("status", "APPROVED")]),
                    ]),
                BinaryNode::new("paging").with_content(vec![text_node("after", "next")]),
            ]),
        ]);
        let catalog = parse_business_catalog(&catalog).unwrap();
        assert_eq!(catalog.next_page_cursor.as_deref(), Some("next"));
        assert_eq!(catalog.products.len(), 1);
        assert_eq!(catalog.products[0].id, "sku-1");
        assert_eq!(catalog.products[0].price, 12_345_000);
        assert!(catalog.products[0].is_hidden);
        assert_eq!(
            catalog.products[0].image_urls.original.as_deref(),
            Some("https://img/full")
        );
        assert_eq!(
            catalog.products[0].review_status.as_deref(),
            Some("APPROVED")
        );
    }

    #[test]
    fn parses_business_collections_and_order_details() {
        let collections =
            BinaryNode::new("iq").with_content(vec![BinaryNode::new("collections").with_content(
                vec![BinaryNode::new("collection").with_content(vec![
                    text_node("id", "collection-1"),
                    text_node("name", "Featured"),
                    sample_product_node(),
                    BinaryNode::new("status_info").with_content(vec![
                        text_node("status", "APPROVED"),
                        text_node("can_appeal", "true"),
                    ]),
                ])],
            )]);
        let collections = parse_business_collections(&collections).unwrap();
        assert_eq!(collections.len(), 1);
        assert_eq!(collections[0].id, "collection-1");
        assert_eq!(collections[0].name, "Featured");
        assert_eq!(collections[0].products[0].id, "sku-1");
        assert_eq!(collections[0].status.status.as_deref(), Some("APPROVED"));
        assert!(collections[0].status.can_appeal);

        let order =
            BinaryNode::new("iq").with_content(vec![BinaryNode::new("order").with_content(vec![
                BinaryNode::new("product").with_content(vec![
                    text_node("id", "sku-1"),
                    text_node("name", "Widget"),
                    BinaryNode::new("image").with_content(vec![text_node("url", "https://img")]),
                    text_node("price", "12345000"),
                    text_node("currency", "USD"),
                    text_node("quantity", "2"),
                ]),
                BinaryNode::new("price").with_content(vec![
                    text_node("total", "24690000"),
                    text_node("currency", "USD"),
                ]),
            ])]);
        let order = parse_business_order_details(&order).unwrap();
        assert_eq!(order.price.total, 24_690_000);
        assert_eq!(order.price.currency, "USD");
        assert_eq!(order.products.len(), 1);
        assert_eq!(order.products[0].quantity, 2);
        assert_eq!(order.products[0].image_url, "https://img");
    }

    #[test]
    fn builds_product_mutation_queries() {
        let create = BusinessProductCreate::new("Widget", "Useful", 12_345_000, "USD")
            .unwrap()
            .with_retailer_id("retailer")
            .with_url("https://example.com/widget")
            .with_images([BusinessProductImage::new("https://img/uploaded").unwrap()])
            .with_origin(BusinessProductOrigin::country_code("US").unwrap())
            .hidden(true);
        let create_node = build_business_product_create_query(create, "q-4").unwrap();
        assert_eq!(create_node.attrs["xmlns"], "w:biz:catalog");
        assert_eq!(create_node.attrs["type"], "set");
        let add = child_node(&create_node, "product_catalog_add").unwrap();
        assert_eq!(add.attrs["v"], "1");
        let product = child_node(add, "product").unwrap();
        assert_eq!(product.attrs["is_hidden"], "true");
        assert_eq!(
            child_text(product, "name").unwrap().as_deref(),
            Some("Widget")
        );
        assert_eq!(
            child_text(product, "price").unwrap().as_deref(),
            Some("12345000")
        );
        let image = child_node(child_node(product, "media").unwrap(), "image").unwrap();
        assert_eq!(
            child_text(image, "url").unwrap().as_deref(),
            Some("https://img/uploaded")
        );
        let compliance = child_node(product, "compliance_info").unwrap();
        assert_eq!(
            child_text(compliance, "country_code_origin")
                .unwrap()
                .as_deref(),
            Some("US")
        );
        assert_eq!(child_text(add, "width").unwrap().as_deref(), Some("100"));

        let update = BusinessProductUpdate::new()
            .with_name("Widget v2")
            .with_price(22)
            .hidden(false);
        let update_node = build_business_product_update_query("sku-1", update, "q-5").unwrap();
        let edit = child_node(&update_node, "product_catalog_edit").unwrap();
        let product = child_node(edit, "product").unwrap();
        assert_eq!(product.attrs["is_hidden"], "false");
        assert_eq!(child_text(product, "id").unwrap().as_deref(), Some("sku-1"));
        assert_eq!(
            child_text(product, "name").unwrap().as_deref(),
            Some("Widget v2")
        );

        let delete_node = build_business_product_delete_query(["sku-1", "sku-2"], "q-6").unwrap();
        let delete = child_node(&delete_node, "product_catalog_delete").unwrap();
        let products = child_nodes(delete)
            .iter()
            .filter(|child| child.tag == "product")
            .collect::<Vec<_>>();
        assert_eq!(products.len(), 2);
        assert_eq!(
            child_text(products[0], "id").unwrap().as_deref(),
            Some("sku-1")
        );
    }

    #[test]
    fn parses_product_mutation_results() {
        let response = BinaryNode::new("iq").with_content(vec![
            BinaryNode::new("product_catalog_add").with_content(vec![sample_product_node()]),
        ]);
        let product = parse_business_product_create_result(&response).unwrap();
        assert_eq!(product.id, "sku-1");
        assert_eq!(
            product.image_urls.requested.as_deref(),
            Some("https://img/requested")
        );

        let response = BinaryNode::new("iq").with_content(vec![
            BinaryNode::new("product_catalog_edit").with_content(vec![sample_product_node()]),
        ]);
        let product = parse_business_product_update_result(&response).unwrap();
        assert_eq!(product.name, "Widget");

        let response = BinaryNode::new("iq").with_content(vec![
            BinaryNode::new("product_catalog_delete").with_attr("deleted_count", "2"),
        ]);
        assert_eq!(parse_business_product_delete_result(&response).unwrap(), 2);
    }

    #[test]
    fn parses_business_mutation_results() {
        let ok = BinaryNode::new("iq").with_attr("type", "result");
        assert!(parse_business_mutation_result(&ok).is_ok());

        let error = BinaryNode::new("iq")
            .with_attr("type", "error")
            .with_attr("code", "403")
            .with_attr("text", "denied");
        assert!(matches!(
            parse_business_mutation_result(&error),
            Err(CoreError::Protocol(message))
                if message == "business mutation failed with code 403: denied"
        ));

        let invalid = BinaryNode::new("message").with_attr("type", "result");
        assert!(parse_business_mutation_result(&invalid).is_err());
    }

    #[test]
    fn converts_uploaded_business_media_to_public_urls() {
        let media = sample_uploaded_media().with_direct_path("/product/image/1");
        let image = business_product_image_from_uploaded_media(&media, Some("media.test")).unwrap();
        assert_eq!(image.url, "https://media.test/product/image/1");

        let cover = business_cover_photo_from_uploaded_media(&media, None).unwrap();
        assert_eq!(cover.url, "https://mmg.whatsapp.net/product/image/1");

        let url_only = sample_uploaded_media().with_url("https://cdn.test/image");
        let image = business_product_image_from_uploaded_media(&url_only, None).unwrap();
        assert_eq!(image.url, "https://cdn.test/image");

        let location = UploadedMediaLocation::new()
            .with_upload_id("fbid-1")
            .with_upload_token("token-1")
            .with_media_key_timestamp(1_700_000_000);
        let upload = business_cover_photo_upload_from_location(&location).unwrap();
        assert_eq!(
            upload,
            BusinessCoverPhotoUpload::new("fbid-1", "token-1", 1_700_000_000).unwrap()
        );

        assert!(business_cover_photo_upload_from_location(&UploadedMediaLocation::new()).is_err());
        assert!(business_cover_photo_from_uploaded_media(&sample_uploaded_media(), None).is_err());
    }

    #[test]
    fn validates_business_inputs() {
        assert!(build_business_profile_query("123@g.us", "q").is_err());
        assert!(
            BusinessCatalogQuery::new("123@s.whatsapp.net")
                .unwrap()
                .with_limit(MAX_BUSINESS_CATALOG_LIMIT + 1)
                .is_err()
        );
        assert!(build_business_profile_update_query(BusinessProfileUpdate::new(), "q").is_err());
        assert!(BusinessProductCreate::new("Widget", "Useful", -1, "USD").is_err());
        assert!(
            build_business_product_update_query("sku", BusinessProductUpdate::new(), "q").is_err()
        );
        assert!(build_business_product_delete_query(Vec::<String>::new(), "q").is_err());
        assert!(
            BusinessCollectionsQuery::new("123@s.whatsapp.net")
                .unwrap()
                .with_collection_limit(MAX_BUSINESS_COLLECTION_LIMIT + 1)
                .is_err()
        );
        assert!(build_business_order_details_query("", "token", "q").is_err());
        assert!(build_business_order_details_query("order", "", "q").is_err());
        assert!(BusinessCoverPhotoUpload::new("", "token", 1).is_err());
        assert!(BusinessCoverPhotoUpload::new("id", "", 1).is_err());
        assert!(BusinessCoverPhotoUpload::new("id", "token", -1).is_err());
        assert!(build_business_cover_photo_delete_query("", "q").is_err());
    }

    fn sample_product_node() -> BinaryNode {
        BinaryNode::new("product")
            .with_attr("is_hidden", "false")
            .with_content(vec![
                text_node("id", "sku-1"),
                text_node("name", "Widget"),
                text_node("retailer_id", "retailer"),
                text_node("description", "Useful"),
                text_node("price", "12345000"),
                text_node("currency", "USD"),
                BinaryNode::new("media").with_content(vec![BinaryNode::new("image").with_content(
                    vec![text_node("request_image_url", "https://img/requested")],
                )]),
                BinaryNode::new("status_info").with_content(vec![text_node("status", "APPROVED")]),
            ])
    }

    fn sample_uploaded_media() -> UploadedMedia {
        UploadedMedia::new(
            Bytes::from_static(&[1u8; 32]),
            Bytes::from_static(&[2u8; 32]),
            Bytes::from_static(&[3u8; 32]),
            12,
        )
    }
}
