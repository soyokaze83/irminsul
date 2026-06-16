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
}
