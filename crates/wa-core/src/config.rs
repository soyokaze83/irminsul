use std::time::Duration;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WaVersion(pub u32, pub u32, pub u32);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Browser {
    pub os: String,
    pub name: String,
    pub version: String,
}

impl Browser {
    #[must_use]
    pub fn macos_chrome() -> Self {
        Self {
            os: "Mac OS".to_owned(),
            name: "Chrome".to_owned(),
            version: "14.4.1".to_owned(),
        }
    }

    #[must_use]
    pub fn macos_desktop() -> Self {
        Self {
            os: "Mac OS".to_owned(),
            name: "Desktop".to_owned(),
            version: "14.4.1".to_owned(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct ClientConfig {
    pub websocket_url: String,
    pub connect_timeout: Duration,
    pub default_query_timeout: Option<Duration>,
    pub keepalive_interval: Duration,
    pub browser: Browser,
    pub version: WaVersion,
    pub mark_online_on_connect: bool,
    pub country_code: String,
    pub push_name: Option<String>,
    pub sync_full_history: bool,
    pub outbound_queue_capacity: usize,
    pub rotate_signed_pre_key_on_connect: bool,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            websocket_url: "wss://web.whatsapp.com/ws/chat".to_owned(),
            connect_timeout: Duration::from_secs(20),
            default_query_timeout: Some(Duration::from_secs(60)),
            keepalive_interval: Duration::from_secs(30),
            browser: Browser::macos_chrome(),
            version: WaVersion(2, 3000, 1035194821),
            mark_online_on_connect: true,
            country_code: "US".to_owned(),
            push_name: None,
            sync_full_history: true,
            outbound_queue_capacity: 128,
            rotate_signed_pre_key_on_connect: false,
        }
    }
}
