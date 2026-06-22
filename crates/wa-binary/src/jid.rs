use std::fmt;
use std::str::FromStr;

pub const S_WHATSAPP_NET: &str = "@s.whatsapp.net";
pub const OFFICIAL_BIZ_JID: &str = "16505361212@c.us";
pub const SERVER_JID: &str = "server@c.us";
pub const PSA_WID: &str = "0@c.us";
pub const STORIES_JID: &str = "status@broadcast";
pub const META_AI_JID: &str = "13135550002@c.us";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum WaJidDomain {
    WhatsApp = 0,
    Lid = 1,
    Hosted = 128,
    HostedLid = 129,
}

impl WaJidDomain {
    #[must_use]
    pub fn server(self, fallback: JidServer) -> JidServer {
        match self {
            Self::WhatsApp => fallback,
            Self::Lid => JidServer::Lid,
            Self::Hosted => JidServer::Hosted,
            Self::HostedLid => JidServer::HostedLid,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JidServer {
    CUs,
    GUs,
    Broadcast,
    SWhatsAppNet,
    Call,
    Lid,
    Newsletter,
    Bot,
    Hosted,
    HostedLid,
    Other,
}

impl JidServer {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CUs => "c.us",
            Self::GUs => "g.us",
            Self::Broadcast => "broadcast",
            Self::SWhatsAppNet => "s.whatsapp.net",
            Self::Call => "call",
            Self::Lid => "lid",
            Self::Newsletter => "newsletter",
            Self::Bot => "bot",
            Self::Hosted => "hosted",
            Self::HostedLid => "hosted.lid",
            Self::Other => "",
        }
    }

    #[must_use]
    pub fn from_server_str(value: &str) -> Self {
        match value {
            "c.us" => Self::CUs,
            "g.us" => Self::GUs,
            "broadcast" => Self::Broadcast,
            "s.whatsapp.net" => Self::SWhatsAppNet,
            "call" => Self::Call,
            "lid" => Self::Lid,
            "newsletter" => Self::Newsletter,
            "bot" => Self::Bot,
            "hosted" => Self::Hosted,
            "hosted.lid" => Self::HostedLid,
            _ => Self::Other,
        }
    }

    #[must_use]
    pub fn domain_type(self, agent: Option<u16>) -> WaJidDomain {
        match self {
            Self::Lid => WaJidDomain::Lid,
            Self::Hosted => WaJidDomain::Hosted,
            Self::HostedLid => WaJidDomain::HostedLid,
            _ if agent == Some(WaJidDomain::Lid as u16) => WaJidDomain::Lid,
            _ if agent == Some(WaJidDomain::Hosted as u16) => WaJidDomain::Hosted,
            _ if agent == Some(WaJidDomain::HostedLid as u16) => WaJidDomain::HostedLid,
            _ => WaJidDomain::WhatsApp,
        }
    }
}

impl fmt::Display for JidServer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FullJid {
    pub user: String,
    pub server: JidServer,
    pub server_raw: String,
    pub device: Option<u16>,
    pub agent: Option<u16>,
    pub domain_type: WaJidDomain,
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum JidParseError {
    #[error("jid is missing @ separator")]
    MissingSeparator,
    #[error("jid has an invalid device id")]
    InvalidDevice,
    #[error("jid has an invalid agent id")]
    InvalidAgent,
}

impl FromStr for FullJid {
    type Err = JidParseError;

    fn from_str(jid: &str) -> Result<Self, Self::Err> {
        jid_decode(jid).ok_or(JidParseError::MissingSeparator)
    }
}

#[must_use]
pub fn jid_encode(
    user: impl ToString,
    server: JidServer,
    device: Option<u16>,
    agent: Option<u16>,
) -> String {
    let user = user.to_string();
    let agent = agent.map(|value| format!("_{value}")).unwrap_or_default();
    let device = device.map(|value| format!(":{value}")).unwrap_or_default();
    format!("{user}{agent}{device}@{}", server.as_str())
}

#[must_use]
pub fn jid_decode(jid: &str) -> Option<FullJid> {
    let (user_combined, server_raw) = jid.split_once('@')?;
    let (user_agent, device_raw) = match user_combined.split_once(':') {
        Some((user_agent, device)) => (user_agent, Some(device)),
        None => (user_combined, None),
    };
    let (user, agent_raw) = match user_agent.split_once('_') {
        Some((user, agent)) => (user, Some(agent)),
        None => (user_agent, None),
    };

    let device = device_raw.and_then(|value| value.parse::<u16>().ok());
    let agent = agent_raw.and_then(|value| value.parse::<u16>().ok());
    let server = JidServer::from_server_str(server_raw);
    let domain_type = server.domain_type(agent);

    Some(FullJid {
        user: user.to_owned(),
        server,
        server_raw: server_raw.to_owned(),
        device,
        agent,
        domain_type,
    })
}

#[must_use]
pub fn jid_normalized_user(jid: &str) -> Option<String> {
    let decoded = jid_decode(jid)?;
    let server = if decoded.server == JidServer::CUs {
        JidServer::SWhatsAppNet
    } else {
        decoded.server
    };
    Some(jid_encode(decoded.user, server, None, None))
}

#[must_use]
pub fn are_jids_same_user(left: &str, right: &str) -> bool {
    jid_decode(left)
        .zip(jid_decode(right))
        .is_some_and(|(left, right)| left.user == right.user)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn decodes_phone_jid() {
        let jid = jid_decode("12345:7@s.whatsapp.net").unwrap();
        assert_eq!(jid.user, "12345");
        assert_eq!(jid.server, JidServer::SWhatsAppNet);
        assert_eq!(jid.device, Some(7));
        assert_eq!(jid.domain_type, WaJidDomain::WhatsApp);
    }

    #[test]
    fn decodes_lid_domain() {
        let jid = jid_decode("abc@lid").unwrap();
        assert_eq!(jid.user, "abc");
        assert_eq!(jid.server, JidServer::Lid);
        assert_eq!(jid.domain_type, WaJidDomain::Lid);
    }

    #[test]
    fn encodes_without_zero_device_suffix() {
        assert_eq!(
            jid_encode("12345", JidServer::SWhatsAppNet, None, None),
            "12345@s.whatsapp.net"
        );
    }

    #[test]
    fn normalizes_c_us_to_s_whatsapp_net() {
        assert_eq!(
            jid_normalized_user("12345@c.us").unwrap(),
            "12345@s.whatsapp.net"
        );
    }

    proptest! {
        #[test]
        fn valid_generated_jids_round_trip(
            user in user_strategy(),
            server in server_strategy(),
            device in prop::option::of(any::<u8>()),
            agent in prop::option::of(agent_strategy()),
        ) {
            let device = device.map(u16::from);
            let jid = jid_encode(&user, server, device, agent);
            let decoded = jid_decode(&jid).unwrap();

            prop_assert_eq!(&decoded.user, &user);
            prop_assert_eq!(decoded.server, server);
            prop_assert_eq!(decoded.server_raw, server.as_str());
            prop_assert_eq!(decoded.device, device);
            prop_assert_eq!(decoded.agent, agent);
            prop_assert_eq!(decoded.domain_type, server.domain_type(agent));

            let encoded_again = jid_encode(
                &decoded.user,
                decoded.server,
                decoded.device,
                decoded.agent,
            );
            prop_assert_eq!(encoded_again, jid);
        }

        #[test]
        fn normalized_user_strips_device_and_maps_c_us(
            user in user_strategy(),
            server in server_strategy(),
            device in prop::option::of(any::<u8>()),
            agent in prop::option::of(agent_strategy()),
        ) {
            let jid = jid_encode(&user, server, device.map(u16::from), agent);
            let normalized = jid_normalized_user(&jid).unwrap();
            let expected_server = if server == JidServer::CUs {
                JidServer::SWhatsAppNet
            } else {
                server
            };

            prop_assert_eq!(&normalized, &jid_encode(&user, expected_server, None, None));
            let decoded = jid_decode(&normalized).unwrap();
            prop_assert_eq!(decoded.user, user);
            prop_assert_eq!(decoded.server, expected_server);
            prop_assert_eq!(decoded.device, None);
            prop_assert_eq!(decoded.agent, None);
        }

        #[test]
        fn same_user_ignores_server_device_and_agent(
            user in user_strategy(),
            left_server in server_strategy(),
            right_server in server_strategy(),
            left_device in prop::option::of(any::<u8>()),
            right_device in prop::option::of(any::<u8>()),
            left_agent in prop::option::of(agent_strategy()),
            right_agent in prop::option::of(agent_strategy()),
        ) {
            let left = jid_encode(&user, left_server, left_device.map(u16::from), left_agent);
            let right = jid_encode(&user, right_server, right_device.map(u16::from), right_agent);
            prop_assert!(are_jids_same_user(&left, &right));
        }

        #[test]
        fn different_users_are_not_same_user(
            left_user in user_strategy(),
            right_user in user_strategy(),
            server in server_strategy(),
        ) {
            prop_assume!(left_user != right_user);
            let left = jid_encode(&left_user, server, None, None);
            let right = jid_encode(&right_user, server, None, None);
            prop_assert!(!are_jids_same_user(&left, &right));
        }
    }

    fn user_strategy() -> impl Strategy<Value = String> {
        prop::collection::vec(
            prop::sample::select(
                "abcdefghijklmnopqrstuvwxyz0123456789"
                    .chars()
                    .collect::<Vec<_>>(),
            ),
            1..=16,
        )
        .prop_map(|chars| chars.into_iter().collect())
    }

    fn server_strategy() -> impl Strategy<Value = JidServer> {
        prop::sample::select(vec![
            JidServer::CUs,
            JidServer::GUs,
            JidServer::Broadcast,
            JidServer::SWhatsAppNet,
            JidServer::Call,
            JidServer::Lid,
            JidServer::Newsletter,
            JidServer::Bot,
            JidServer::Hosted,
            JidServer::HostedLid,
        ])
    }

    fn agent_strategy() -> impl Strategy<Value = u16> {
        prop::sample::select(vec![
            WaJidDomain::Lid as u16,
            WaJidDomain::Hosted as u16,
            WaJidDomain::HostedLid as u16,
            2,
            7,
        ])
    }
}
