#![forbid(unsafe_code)]

use bytes::Bytes;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use wa_binary::BinaryNode;

#[must_use]
pub fn ping_node() -> BinaryNode {
    BinaryNode::new("iq").with_attr("type", "get")
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct BinaryNodeFixtureManifest {
    pub schema: String,
    pub source: String,
    pub fixtures: Vec<BinaryNodeFixture>,
}

impl BinaryNodeFixtureManifest {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, FixtureError> {
        let bytes = fs::read(path)?;
        Ok(serde_json::from_slice(&bytes)?)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct SignalFixtureManifest {
    pub schema: String,
    pub source: String,
    pub vectors: Vec<SignalFixture>,
}

impl SignalFixtureManifest {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, FixtureError> {
        let bytes = fs::read(path)?;
        Ok(serde_json::from_slice(&bytes)?)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SignalFixture {
    MessageBody(SignalMessageBodyFixture),
    MessageChain(SignalMessageChainFixture),
    PreKeyRootChain(SignalPreKeyRootChainFixture),
    PreKeySessionPreKeyIdMismatch(SignalPreKeySessionPreKeyIdMismatchFixture),
    PreKeySessionPreKeyStateMismatch(SignalPreKeySessionPreKeyStateMismatchFixture),
    PreKeySessionUnexpectedPreKeyStateMismatch(
        SignalPreKeySessionUnexpectedPreKeyStateMismatchFixture,
    ),
    PreKeySessionInvalidSignedPreKey(SignalPreKeySessionInvalidSignedPreKeyFixture),
    PreKeySessionInvalidPreKey(SignalPreKeySessionInvalidPreKeyFixture),
    PreKeySessionMessage(SignalPreKeySessionMessageFixture),
    PreKeySessionMessageNoOneTime(SignalPreKeySessionMessageNoOneTimeFixture),
    PreKeySessionSignedPreKeyIdMismatch(SignalPreKeySessionSignedPreKeyIdMismatchFixture),
    PreKeyWhisperMessage(SignalPreKeyWhisperMessageFixture),
    PreKeyWhisperMessageMissingInnerPreviousCounter(
        SignalPreKeyWhisperMessageMissingInnerPreviousCounterFixture,
    ),
    PreKeyWhisperMessageUnknownField(SignalPreKeyWhisperMessageUnknownFieldFixture),
    PreKeyWhisperInvalidBaseKey(SignalPreKeyWhisperInvalidBaseKeyFixture),
    PreKeyWhisperInvalidIdentityKey(SignalPreKeyWhisperInvalidIdentityKeyFixture),
    PreKeyWhisperInvalidWire(SignalPreKeyWhisperInvalidWireFixture),
    ProviderSessionBidirectional(SignalProviderSessionBidirectionalFixture),
    ProviderSessionFarFutureCounter(SignalProviderSessionFarFutureCounterFixture),
    ProviderSessionFarFuturePreviousCounter(SignalProviderSessionFarFuturePreviousCounterFixture),
    ProviderSessionStalePreviousCounter(SignalProviderSessionStalePreviousCounterFixture),
    ProviderSessionMessage(SignalProviderSessionMessageFixture),
    ProviderSessionInvalidRecord(SignalProviderSessionInvalidRecordFixture),
    ProviderSessionInvalidWire(SignalProviderSessionInvalidWireFixture),
    ProviderSessionInvalidSkippedKey(SignalProviderSessionInvalidSkippedKeyFixture),
    ProviderSessionNewRatchetReplay(SignalProviderSessionNewRatchetReplayFixture),
    ProviderSessionNewRatchetTamperReject(SignalProviderSessionNewRatchetTamperRejectFixture),
    ProviderSessionOutOfOrder(SignalProviderSessionOutOfOrderFixture),
    ProviderSessionPreviousChainReplay(SignalProviderSessionPreviousChainReplayFixture),
    ProviderSessionPrunedSkippedKeys(SignalProviderSessionPrunedSkippedKeysFixture),
    ProviderSessionReplayReject(SignalProviderSessionReplayRejectFixture),
    ProviderSessionRatchetStep(SignalProviderSessionRatchetStepFixture),
    ProviderSessionRecord(SignalProviderSessionRecordFixture),
    ProviderSessionFutureTamperReject(SignalProviderSessionFutureTamperRejectFixture),
    ProviderSessionTamperReject(SignalProviderSessionTamperRejectFixture),
    SenderChain(SignalSenderChainFixture),
    SenderMessageBody(SignalSenderMessageBodyFixture),
    SenderKeyDistribution(SignalSenderKeyDistributionFixture),
    SenderKeyDistributionUnknownField(SignalSenderKeyDistributionUnknownFieldFixture),
    SenderKeyDistributionInvalidWire(SignalSenderKeyDistributionInvalidWireFixture),
    SenderKeyDistributionMerge(SignalSenderKeyDistributionMergeFixture),
    SenderKeyDistributionReplace(SignalSenderKeyDistributionReplaceFixture),
    SenderKeyDistributionStale(SignalSenderKeyDistributionStaleFixture),
    SenderKeyDistributionCacheStale(SignalSenderKeyDistributionCacheStaleFixture),
    SenderKeyDistributionStaleChainRetry(SignalSenderKeyDistributionStaleChainRetryFixture),
    SenderKeyDistributionTruncate(SignalSenderKeyDistributionTruncateFixture),
    SenderKeyRecordOutOfOrder(SignalSenderKeyRecordOutOfOrderFixture),
    SenderKeyRecordFarFuture(SignalSenderKeyRecordFarFutureFixture),
    SenderKeyRecordMultiStateDecrypt(SignalSenderKeyRecordMultiStateDecryptFixture),
    SenderKeyRecordMessage(SignalSenderKeyRecordMessageFixture),
    SenderKeyRecordInvalidWire(SignalSenderKeyRecordInvalidWireFixture),
    SenderKeyRecordUnknownField(SignalSenderKeyRecordUnknownFieldFixture),
    SenderKeyMessageInvalidWire(SignalSenderKeyMessageInvalidWireFixture),
    SenderKeyMessageUnknownField(SignalSenderKeyMessageUnknownFieldFixture),
    SenderKeyMessageInvalidSignature(SignalSenderKeyMessageInvalidSignatureFixture),
    SenderKeyRecordInvalidState(SignalSenderKeyRecordInvalidStateFixture),
    SenderKeyRecordInvalidSigningKey(SignalSenderKeyRecordInvalidSigningKeyFixture),
    SenderKeyRecord(SignalSenderKeyRecordFixture),
    WhisperMessageMissingPreviousCounter(SignalWhisperMessageMissingPreviousCounterFixture),
    WhisperMessageUnknownField(SignalWhisperMessageUnknownFieldFixture),
    WhisperInvalidWire(SignalWhisperInvalidWireFixture),
    WhisperMessage(SignalWhisperMessageFixture),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct SignalMessageChainFixture {
    pub name: String,
    pub chain_key_hex: String,
    pub counter: u32,
    pub message_counter: u32,
    pub message_key_seed_hex: String,
    pub cipher_key_hex: String,
    pub mac_key_hex: String,
    pub iv_hex: String,
    pub next_chain_key_hex: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct SignalMessageBodyFixture {
    pub name: String,
    pub cipher_key_hex: String,
    pub mac_key_hex: String,
    pub iv_hex: String,
    pub plaintext_hex: String,
    pub ciphertext_hex: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct SignalPreKeyRootChainFixture {
    pub name: String,
    pub alice_identity_private_hex: String,
    pub alice_base_private_hex: String,
    pub bob_identity_private_hex: String,
    pub bob_signed_pre_key_private_hex: String,
    pub bob_one_time_pre_key_private_hex: String,
    pub root_key_hex: String,
    pub chain_key_hex: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct SignalPreKeySessionMessageFixture {
    pub name: String,
    pub alice_registration_id: u32,
    pub bob_registration_id: u32,
    pub bob_signed_pre_key_id: u32,
    pub bob_one_time_pre_key_id: u32,
    pub alice_identity_private_hex: String,
    pub alice_base_private_hex: String,
    /// Initiator's fresh sending-ratchet key (libsignal `calculateSendingRatchet`),
    /// supplied explicitly so the outbound wire bytes are deterministic.
    #[serde(default)]
    pub alice_sending_ratchet_private_hex: String,
    pub bob_identity_private_hex: String,
    pub bob_signed_pre_key_private_hex: String,
    pub bob_one_time_pre_key_private_hex: String,
    pub plaintext_hex: String,
    pub tampered_message_hex: Option<String>,
    pub expected_tamper_error: Option<String>,
    pub expected_replay_error: String,
    pub message_hex: String,
    pub message_outer_unknown_field_hex: Option<String>,
    pub message_inner_unknown_field_hex: Option<String>,
    pub sender_record_hex: String,
    pub receiver_record_hex: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct SignalPreKeySessionInvalidSignedPreKeyFixture {
    pub name: String,
    pub alice_registration_id: u32,
    pub bob_registration_id: u32,
    pub bob_signed_pre_key_id: u32,
    pub bob_one_time_pre_key_id: u32,
    pub alice_identity_private_hex: String,
    pub alice_base_private_hex: String,
    pub bob_identity_private_hex: String,
    pub bob_signed_pre_key_private_hex: String,
    pub bob_one_time_pre_key_private_hex: String,
    pub invalid_identity_key_hex: Option<String>,
    pub invalid_signed_pre_key_public_key_hex: Option<String>,
    pub invalid_signature_hex: String,
    pub plaintext_hex: String,
    pub expected_error: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct SignalPreKeySessionInvalidPreKeyFixture {
    pub name: String,
    pub alice_registration_id: u32,
    pub bob_registration_id: u32,
    pub bob_signed_pre_key_id: u32,
    pub bob_one_time_pre_key_id: u32,
    pub alice_identity_private_hex: String,
    pub alice_base_private_hex: String,
    pub bob_identity_private_hex: String,
    pub bob_signed_pre_key_private_hex: String,
    pub bob_one_time_pre_key_private_hex: String,
    pub invalid_one_time_pre_key_public_key_hex: String,
    pub plaintext_hex: String,
    pub expected_error: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct SignalPreKeySessionPreKeyIdMismatchFixture {
    pub name: String,
    pub alice_registration_id: u32,
    pub bob_registration_id: u32,
    pub bob_signed_pre_key_id: u32,
    pub bob_one_time_pre_key_id: u32,
    pub mismatched_one_time_pre_key_id: u32,
    pub alice_identity_private_hex: String,
    pub alice_base_private_hex: String,
    #[serde(default)]
    pub alice_sending_ratchet_private_hex: String,
    pub bob_identity_private_hex: String,
    pub bob_signed_pre_key_private_hex: String,
    pub bob_one_time_pre_key_private_hex: String,
    pub plaintext_hex: String,
    pub mismatched_message_hex: String,
    pub expected_error: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct SignalPreKeySessionPreKeyStateMismatchFixture {
    pub name: String,
    pub alice_registration_id: u32,
    pub bob_registration_id: u32,
    pub bob_signed_pre_key_id: u32,
    pub bob_one_time_pre_key_id: u32,
    pub alice_identity_private_hex: String,
    pub alice_base_private_hex: String,
    #[serde(default)]
    pub alice_sending_ratchet_private_hex: String,
    pub bob_identity_private_hex: String,
    pub bob_signed_pre_key_private_hex: String,
    pub bob_one_time_pre_key_private_hex: String,
    pub plaintext_hex: String,
    pub message_hex: String,
    pub expected_error: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct SignalPreKeySessionUnexpectedPreKeyStateMismatchFixture {
    pub name: String,
    pub alice_registration_id: u32,
    pub bob_registration_id: u32,
    pub bob_signed_pre_key_id: u32,
    pub unexpected_one_time_pre_key_id: u32,
    pub alice_identity_private_hex: String,
    pub alice_base_private_hex: String,
    #[serde(default)]
    pub alice_sending_ratchet_private_hex: String,
    pub bob_identity_private_hex: String,
    pub bob_signed_pre_key_private_hex: String,
    pub unexpected_one_time_pre_key_private_hex: String,
    pub plaintext_hex: String,
    pub message_hex: String,
    pub expected_error: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct SignalPreKeySessionSignedPreKeyIdMismatchFixture {
    pub name: String,
    pub alice_registration_id: u32,
    pub bob_registration_id: u32,
    pub bob_signed_pre_key_id: u32,
    pub mismatched_signed_pre_key_id: u32,
    pub bob_one_time_pre_key_id: u32,
    pub alice_identity_private_hex: String,
    pub alice_base_private_hex: String,
    #[serde(default)]
    pub alice_sending_ratchet_private_hex: String,
    pub bob_identity_private_hex: String,
    pub bob_signed_pre_key_private_hex: String,
    pub bob_one_time_pre_key_private_hex: String,
    pub plaintext_hex: String,
    pub mismatched_message_hex: String,
    pub expected_error: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct SignalPreKeySessionMessageNoOneTimeFixture {
    pub name: String,
    pub alice_registration_id: u32,
    pub bob_registration_id: u32,
    pub bob_signed_pre_key_id: u32,
    pub alice_identity_private_hex: String,
    pub alice_base_private_hex: String,
    #[serde(default)]
    pub alice_sending_ratchet_private_hex: String,
    pub bob_identity_private_hex: String,
    pub bob_signed_pre_key_private_hex: String,
    pub plaintext_hex: String,
    pub tampered_message_hex: Option<String>,
    pub expected_tamper_error: Option<String>,
    pub expected_replay_error: String,
    pub message_hex: String,
    pub message_outer_unknown_field_hex: Option<String>,
    pub message_inner_unknown_field_hex: Option<String>,
    pub sender_record_hex: String,
    pub receiver_record_hex: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct SignalPreKeyWhisperMessageFixture {
    pub name: String,
    pub registration_id: u32,
    pub pre_key_id: Option<u32>,
    pub signed_pre_key_id: u32,
    pub base_key_hex: String,
    pub identity_key_hex: String,
    pub ephemeral_key_hex: String,
    pub counter: u32,
    pub previous_counter: u32,
    pub ciphertext_hex: String,
    pub encoded_hex: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct SignalPreKeyWhisperMessageMissingInnerPreviousCounterFixture {
    pub name: String,
    pub registration_id: u32,
    pub pre_key_id: Option<u32>,
    pub signed_pre_key_id: u32,
    pub base_key_hex: String,
    pub identity_key_hex: String,
    pub ephemeral_key_hex: String,
    pub counter: u32,
    pub ciphertext_hex: String,
    pub encoded_hex: String,
    pub canonical_encoded_hex: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct SignalPreKeyWhisperMessageUnknownFieldFixture {
    pub name: String,
    pub registration_id: u32,
    pub pre_key_id: Option<u32>,
    pub signed_pre_key_id: u32,
    pub base_key_hex: String,
    pub identity_key_hex: String,
    pub ephemeral_key_hex: String,
    pub counter: u32,
    pub previous_counter: u32,
    pub ciphertext_hex: String,
    pub encoded_hex: String,
    pub canonical_encoded_hex: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct SignalPreKeyWhisperInvalidBaseKeyFixture {
    pub name: String,
    pub registration_id: u32,
    pub pre_key_id: Option<u32>,
    pub signed_pre_key_id: u32,
    pub base_key_hex: String,
    pub identity_key_hex: String,
    pub ephemeral_key_hex: String,
    pub counter: u32,
    pub previous_counter: u32,
    pub ciphertext_hex: String,
    pub expected_error: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct SignalPreKeyWhisperInvalidIdentityKeyFixture {
    pub name: String,
    pub registration_id: u32,
    pub pre_key_id: Option<u32>,
    pub signed_pre_key_id: u32,
    pub base_key_hex: String,
    pub identity_key_hex: String,
    pub ephemeral_key_hex: String,
    pub counter: u32,
    pub previous_counter: u32,
    pub ciphertext_hex: String,
    pub expected_error: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct SignalPreKeyWhisperInvalidWireFixture {
    pub name: String,
    pub encoded_hex: String,
    pub expected_error: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct SignalProviderSessionMessageFixture {
    pub name: String,
    pub remote_registration_id: u32,
    pub remote_identity_key_hex: String,
    pub root_key_hex: String,
    pub sending_chain_key_hex: String,
    pub sending_counter: u32,
    pub sender_remote_ratchet_key_hex: String,
    pub sender_receiving_chain_key_hex: String,
    pub sender_receiving_counter: u32,
    pub sender_local_ratchet_private_hex: String,
    pub receiver_local_ratchet_private_hex: String,
    pub previous_counter: u32,
    pub plaintext_hex: String,
    pub message_hex: String,
    pub message_with_unknown_field_hex: Option<String>,
    pub sender_record_hex: String,
    pub receiver_record_hex: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct SignalProviderSessionFarFutureCounterFixture {
    pub name: String,
    pub remote_registration_id: u32,
    pub remote_identity_key_hex: String,
    pub root_key_hex: String,
    pub sending_chain_key_hex: String,
    pub sending_counter: u32,
    pub sender_local_ratchet_private_hex: String,
    pub receiver_local_ratchet_private_hex: String,
    pub previous_counter: u32,
    pub valid_plaintext_hex: String,
    pub far_future_counter: u32,
    pub far_future_ciphertext_hex: String,
    pub far_future_message_hex: String,
    pub receiver_record_before_reject_hex: String,
    pub valid_message_hex: String,
    pub sender_record_after_valid_hex: String,
    pub receiver_record_after_valid_hex: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct SignalProviderSessionFarFuturePreviousCounterFixture {
    pub name: String,
    pub remote_registration_id: u32,
    pub remote_identity_key_hex: String,
    pub root_key_hex: String,
    pub sending_chain_key_hex: String,
    pub sending_counter: u32,
    pub sender_local_ratchet_private_hex: String,
    pub receiver_local_ratchet_private_hex: String,
    pub new_remote_ratchet_private_hex: String,
    pub previous_counter: u32,
    pub valid_plaintext_hex: String,
    pub far_future_counter: u32,
    pub far_future_previous_counter: u32,
    pub far_future_ciphertext_hex: String,
    pub far_future_message_hex: String,
    pub receiver_record_before_reject_hex: String,
    pub valid_message_hex: String,
    pub sender_record_after_valid_hex: String,
    pub receiver_record_after_valid_hex: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct SignalProviderSessionStalePreviousCounterFixture {
    pub name: String,
    pub remote_registration_id: u32,
    pub remote_identity_key_hex: String,
    pub root_key_hex: String,
    pub receiving_chain_key_hex: String,
    pub receiving_counter: u32,
    pub sender_ratchet_private_hex: String,
    pub receiver_local_ratchet_private_hex: String,
    pub new_remote_ratchet_private_hex: String,
    pub previous_counter: u32,
    pub stale_counter: u32,
    pub stale_previous_counter: u32,
    pub stale_ciphertext_hex: String,
    pub stale_message_hex: String,
    pub receiver_record_before_reject_hex: String,
    pub valid_plaintext_hex: String,
    pub valid_message_hex: String,
    pub receiver_record_after_valid_hex: String,
    pub expected_error: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct SignalProviderSessionReplayRejectFixture {
    pub name: String,
    pub remote_registration_id: u32,
    pub remote_identity_key_hex: String,
    pub root_key_hex: String,
    pub sending_chain_key_hex: String,
    pub sending_counter: u32,
    pub sender_local_ratchet_private_hex: String,
    pub receiver_local_ratchet_private_hex: String,
    pub previous_counter: u32,
    pub first_plaintext_hex: String,
    pub second_plaintext_hex: String,
    pub expected_replay_error: String,
    pub receiver_record_before_reject_hex: String,
    pub first_message_hex: String,
    pub second_message_hex: String,
    pub sender_record_after_first_hex: String,
    pub sender_record_after_second_hex: String,
    pub receiver_record_after_first_hex: String,
    pub receiver_record_after_second_hex: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct SignalProviderSessionNewRatchetReplayFixture {
    pub name: String,
    pub remote_registration_id: u32,
    pub remote_identity_key_hex: String,
    pub root_key_hex: String,
    pub sending_chain_key_hex: String,
    pub sending_counter: u32,
    pub receiving_chain_key_hex: String,
    pub receiving_counter: u32,
    pub old_remote_ratchet_key_hex: String,
    pub local_ratchet_private_hex: String,
    pub new_remote_ratchet_private_hex: String,
    pub previous_counter: u32,
    pub message_previous_counter: u32,
    pub first_plaintext_hex: String,
    pub next_plaintext_hex: String,
    pub expected_replay_error: String,
    pub receiver_record_before_reject_hex: String,
    pub first_message_hex: String,
    pub next_message_hex: String,
    pub receiver_record_after_first_hex: String,
    pub receiver_record_after_next_hex: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct SignalProviderSessionNewRatchetTamperRejectFixture {
    pub name: String,
    pub remote_registration_id: u32,
    pub remote_identity_key_hex: String,
    pub root_key_hex: String,
    pub sending_chain_key_hex: String,
    pub sending_counter: u32,
    pub receiving_chain_key_hex: String,
    pub receiving_counter: u32,
    pub old_remote_ratchet_key_hex: String,
    pub local_ratchet_private_hex: String,
    pub new_remote_ratchet_private_hex: String,
    pub previous_counter: u32,
    pub message_previous_counter: u32,
    pub plaintext_hex: String,
    pub expected_error: String,
    pub tampered_message_hex: String,
    pub valid_message_hex: String,
    pub receiver_record_before_reject_hex: String,
    pub receiver_record_after_valid_hex: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct SignalProviderSessionTamperRejectFixture {
    pub name: String,
    pub remote_registration_id: u32,
    pub remote_identity_key_hex: String,
    pub root_key_hex: String,
    pub sending_chain_key_hex: String,
    pub sending_counter: u32,
    pub sender_local_ratchet_private_hex: String,
    pub receiver_local_ratchet_private_hex: String,
    pub previous_counter: u32,
    pub plaintext_hex: String,
    pub tampered_message_hex: String,
    pub valid_message_hex: String,
    pub receiver_record_before_reject_hex: String,
    pub sender_record_after_valid_hex: String,
    pub receiver_record_after_valid_hex: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct SignalProviderSessionFutureTamperRejectFixture {
    pub name: String,
    pub remote_registration_id: u32,
    pub remote_identity_key_hex: String,
    pub root_key_hex: String,
    pub receiving_chain_key_hex: String,
    pub receiving_counter: u32,
    pub remote_ratchet_private_hex: String,
    pub local_ratchet_private_hex: String,
    pub previous_counter: u32,
    pub skipped_plaintext_hex: String,
    pub target_plaintext_hex: String,
    pub next_plaintext_hex: String,
    pub expected_error: String,
    pub tampered_message_hex: String,
    pub skipped_message_hex: String,
    pub target_message_hex: String,
    pub next_message_hex: String,
    pub receiver_record_before_reject_hex: String,
    pub receiver_record_after_target_hex: String,
    pub receiver_record_after_skipped_hex: String,
    pub receiver_record_after_next_hex: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct SignalProviderSessionBidirectionalFixture {
    pub name: String,
    pub alice_registration_id: u32,
    pub bob_registration_id: u32,
    pub alice_identity_key_hex: String,
    pub bob_identity_key_hex: String,
    pub root_key_hex: String,
    pub alice_sending_chain_key_hex: String,
    pub alice_sending_counter: u32,
    pub bob_sending_chain_key_hex: String,
    pub bob_sending_counter: u32,
    pub alice_local_ratchet_private_hex: String,
    pub bob_local_ratchet_private_hex: String,
    pub alice_previous_counter: u32,
    pub bob_previous_counter: u32,
    pub alice_plaintext_hex: String,
    pub bob_plaintext_hex: String,
    pub alice_message_hex: String,
    pub bob_message_hex: String,
    pub alice_record_after_send_hex: String,
    pub bob_record_after_receive_hex: String,
    pub bob_record_after_reply_hex: String,
    pub alice_record_after_reply_hex: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct SignalProviderSessionOutOfOrderFixture {
    pub name: String,
    pub remote_registration_id: u32,
    pub remote_identity_key_hex: String,
    pub root_key_hex: String,
    pub sending_chain_key_hex: String,
    pub sending_counter: u32,
    pub sender_remote_ratchet_key_hex: String,
    pub sender_receiving_chain_key_hex: String,
    pub sender_receiving_counter: u32,
    pub sender_local_ratchet_private_hex: String,
    pub receiver_local_ratchet_private_hex: String,
    pub previous_counter: u32,
    pub first_plaintext_hex: String,
    pub second_plaintext_hex: String,
    pub third_plaintext_hex: String,
    pub expected_tamper_error: String,
    pub expected_replay_error: String,
    pub receiver_record_before_reject_hex: String,
    pub first_message_hex: String,
    pub second_message_hex: String,
    pub third_message_hex: String,
    pub tampered_first_message_hex: String,
    pub sender_record_hex: String,
    pub sender_record_after_third_hex: String,
    pub receiver_record_after_second_hex: String,
    pub receiver_record_after_first_hex: String,
    pub receiver_record_after_third_hex: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct SignalProviderSessionPrunedSkippedKeysFixture {
    pub name: String,
    pub remote_registration_id: u32,
    pub remote_identity_key_hex: String,
    pub root_key_hex: String,
    pub receiving_chain_key_hex: String,
    pub receiving_counter: u32,
    pub sender_ratchet_private_hex: String,
    pub receiver_local_ratchet_private_hex: String,
    pub previous_counter: u32,
    pub target_counter: u32,
    pub first_plaintext_hex: String,
    pub second_plaintext_hex: String,
    pub target_plaintext_hex: String,
    pub expected_retained_skipped_count: usize,
    pub expected_oldest_retained_counter: u32,
    pub expected_newest_retained_counter: u32,
    pub expected_retained_after_second_count: usize,
    pub expected_oldest_after_second_counter: u32,
    pub pruned_replay_expected_error: String,
    pub first_message_hex: String,
    pub second_message_hex: String,
    pub target_message_hex: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct SignalProviderSessionInvalidSkippedKeyFixture {
    pub name: String,
    pub remote_registration_id: u32,
    pub remote_identity_key_hex: String,
    pub root_key_hex: String,
    pub sending_chain_key_hex: String,
    pub sending_counter: u32,
    pub receiving_chain_key_hex: String,
    pub receiving_counter: u32,
    pub remote_ratchet_key_hex: String,
    pub local_ratchet_private_hex: String,
    pub previous_counter: u32,
    pub skipped_counter: u32,
    pub skipped_cipher_key_hex: String,
    pub skipped_mac_key_hex: String,
    pub skipped_iv_hex: String,
    pub expected_error: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct SignalProviderSessionInvalidRecordFixture {
    pub name: String,
    pub remote_registration_id: u32,
    pub remote_identity_key_hex: String,
    pub root_key_hex: String,
    pub sending_chain_key_hex: String,
    pub sending_counter: u32,
    pub receiving_chain_key_hex: Option<String>,
    pub receiving_counter: Option<u32>,
    pub remote_ratchet_key_hex: Option<String>,
    pub local_ratchet_private_hex: String,
    pub local_ratchet_public_hex: Option<String>,
    pub previous_counter: u32,
    pub skipped_ratchet_key_hex: Option<String>,
    pub skipped_counter: Option<u32>,
    pub skipped_cipher_key_hex: Option<String>,
    pub skipped_mac_key_hex: Option<String>,
    pub skipped_iv_hex: Option<String>,
    #[serde(default)]
    pub extra_skipped_keys: Vec<SignalProviderSessionInvalidRecordSkippedKeyFixture>,
    pub expected_error: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct SignalProviderSessionInvalidWireFixture {
    pub name: String,
    pub encoded_hex: String,
    pub expected_error: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct SignalProviderSessionInvalidRecordSkippedKeyFixture {
    pub ratchet_key_hex: String,
    pub counter: u32,
    pub cipher_key_hex: String,
    pub mac_key_hex: String,
    pub iv_hex: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct SignalProviderSessionRatchetStepFixture {
    pub name: String,
    pub remote_registration_id: u32,
    pub remote_identity_key_hex: String,
    pub root_key_hex: String,
    pub sending_chain_key_hex: String,
    pub sending_counter: u32,
    pub receiving_chain_key_hex: String,
    pub receiving_counter: u32,
    pub old_remote_ratchet_key_hex: String,
    pub local_ratchet_private_hex: String,
    pub new_remote_ratchet_private_hex: String,
    pub previous_counter: u32,
    pub message_previous_counter: u32,
    pub plaintext_hex: String,
    pub message_hex: String,
    pub receiver_record_hex: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct SignalProviderSessionPreviousChainReplayFixture {
    pub name: String,
    pub remote_registration_id: u32,
    pub remote_identity_key_hex: String,
    pub root_key_hex: String,
    pub sending_chain_key_hex: String,
    pub sending_counter: u32,
    pub receiving_chain_key_hex: String,
    pub receiving_counter: u32,
    pub old_remote_ratchet_key_hex: String,
    pub local_ratchet_private_hex: String,
    pub new_remote_ratchet_private_hex: String,
    pub previous_counter: u32,
    pub message_previous_counter: u32,
    pub old_plaintext_hex: String,
    pub tampered_old_message_hex: Option<String>,
    pub expected_tamper_error: Option<String>,
    pub receiver_record_before_old_reject_hex: String,
    #[serde(default)]
    pub expected_old_replay_error: Option<String>,
    pub receiver_record_before_old_replay_hex: String,
    pub second_old_plaintext_hex: Option<String>,
    pub new_plaintext_hex: String,
    pub next_new_plaintext_hex: Option<String>,
    pub old_message_hex: String,
    pub second_old_message_hex: Option<String>,
    pub new_message_hex: String,
    pub next_new_message_hex: Option<String>,
    pub receiver_record_after_new_hex: String,
    pub receiver_record_after_old_hex: String,
    pub receiver_record_after_second_old_hex: Option<String>,
    pub receiver_record_after_next_new_hex: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct SignalProviderSessionRecordFixture {
    pub name: String,
    pub remote_registration_id: u32,
    pub remote_identity_key_hex: String,
    pub root_key_hex: String,
    pub sending_chain_key_hex: String,
    pub sending_counter: u32,
    pub receiving_chain_key_hex: String,
    pub receiving_counter: u32,
    pub remote_ratchet_key_hex: String,
    pub local_ratchet_private_hex: String,
    pub previous_counter: u32,
    pub skipped_ratchet_key_hex: String,
    pub skipped_counter: u32,
    pub skipped_cipher_key_hex: String,
    pub skipped_mac_key_hex: String,
    pub skipped_iv_hex: String,
    pub encoded_hex: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct SignalSenderChainFixture {
    pub name: String,
    pub chain_key_hex: String,
    pub iteration: u32,
    pub message_key_seed_hex: String,
    pub cipher_key_hex: String,
    pub iv_hex: String,
    pub next_chain_key_hex: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct SignalSenderMessageBodyFixture {
    pub name: String,
    pub cipher_key_hex: String,
    pub iv_hex: String,
    pub plaintext_hex: String,
    pub ciphertext_hex: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct SignalSenderKeyDistributionFixture {
    pub name: String,
    pub key_id: u32,
    pub iteration: u32,
    pub chain_key_hex: String,
    pub signing_public_key_hex: String,
    pub encoded_hex: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct SignalSenderKeyDistributionUnknownFieldFixture {
    pub name: String,
    pub key_id: u32,
    pub iteration: u32,
    pub chain_key_hex: String,
    pub signing_public_key_hex: String,
    pub encoded_hex: String,
    pub canonical_encoded_hex: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct SignalSenderKeyDistributionInvalidWireFixture {
    pub name: String,
    pub encoded_hex: String,
    pub expected_error: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct SignalSenderKeyDistributionMergeFixture {
    pub name: String,
    pub key_id: u32,
    pub existing_chain_key_hex: String,
    pub existing_chain_iteration: u32,
    pub distribution_chain_key_hex: String,
    pub distribution_iteration: u32,
    pub signing_public_key_hex: String,
    pub signing_private_key_hex: String,
    pub skipped_iteration: u32,
    pub skipped_seed_hex: String,
    pub replaced_signing_public_key_hex: String,
    pub preserved_key_id: u32,
    pub preserved_chain_key_hex: String,
    pub preserved_chain_iteration: u32,
    pub preserved_signing_public_key_hex: String,
    pub updated_record_hex: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct SignalSenderKeyDistributionReplaceFixture {
    pub name: String,
    pub key_id: u32,
    pub existing_chain_key_hex: String,
    pub existing_chain_iteration: u32,
    pub existing_signing_public_key_hex: String,
    pub existing_signing_private_key_hex: String,
    pub replacement_chain_key_hex: String,
    pub replacement_iteration: u32,
    pub replacement_signing_public_key_hex: String,
    pub replacement_signing_private_key_hex: String,
    pub skipped_iteration: u32,
    pub skipped_seed_hex: String,
    pub preserved_key_id: u32,
    pub preserved_chain_key_hex: String,
    pub preserved_chain_iteration: u32,
    pub preserved_signing_public_key_hex: String,
    pub updated_record_hex: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct SignalSenderKeyDistributionStaleFixture {
    pub name: String,
    pub key_id: u32,
    pub existing_chain_key_hex: String,
    pub existing_chain_iteration: u32,
    pub stale_chain_key_hex: String,
    pub stale_iteration: u32,
    pub signing_public_key_hex: String,
    pub signing_private_key_hex: String,
    pub skipped_iteration: u32,
    pub skipped_seed_hex: String,
    pub updated_record_hex: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct SignalSenderKeyDistributionCacheStaleFixture {
    pub name: String,
    pub key_id: u32,
    pub existing_chain_key_hex: String,
    pub existing_iteration: u32,
    pub incoming_chain_key_hex: String,
    pub incoming_iteration: u32,
    pub signing_public_key_hex: String,
    pub signing_private_key_hex: String,
    pub existing_distribution_hex: String,
    pub incoming_distribution_hex: String,
    pub expected_cached_distribution_hex: String,
    pub equal_iteration_chain_key_hex: String,
    pub equal_iteration: u32,
    pub equal_iteration_distribution_hex: String,
    pub expected_equal_iteration_cached_distribution_hex: String,
    pub replacement_chain_key_hex: String,
    pub replacement_iteration: u32,
    pub replacement_signing_private_key_hex: String,
    pub replacement_signing_public_key_hex: String,
    pub replacement_distribution_hex: String,
    pub expected_replacement_cached_distribution_hex: String,
    pub malformed_incoming_distribution_hex: String,
    pub malformed_incoming_error: String,
    pub expected_cached_after_malformed_distribution_hex: String,
    pub malformed_existing_distribution_hex: String,
    pub expected_cached_after_malformed_existing_distribution_hex: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct SignalSenderKeyDistributionStaleChainRetryFixture {
    pub name: String,
    pub key_id: u32,
    pub stale_chain_key_hex: String,
    pub stale_iteration: u32,
    pub fresh_chain_key_hex: String,
    pub fresh_iteration: u32,
    pub signing_public_key_hex: String,
    pub signing_private_key_hex: String,
    pub plaintext_hex: String,
    pub stale_decrypt_error: String,
    pub tampered_decrypt_error: String,
    pub stale_record_hex: String,
    pub fresh_distribution_hex: String,
    pub fresh_ciphertext_hex: String,
    pub tampered_ciphertext_hex: String,
    pub candidate_record_hex: String,
    pub recovered_record_hex: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct SignalSenderKeyDistributionTruncateFixture {
    pub name: String,
    pub key_id: u32,
    pub distribution_chain_key_hex: String,
    pub distribution_iteration: u32,
    pub distribution_signing_public_key_hex: String,
    pub existing_key_ids: Vec<u32>,
    pub existing_chain_iteration: u32,
    pub expected_key_ids: Vec<u32>,
    pub dropped_key_id: u32,
    pub updated_record_hex: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct SignalSenderKeyRecordFixture {
    pub name: String,
    pub key_id: u32,
    pub chain_key_hex: String,
    pub chain_iteration: u32,
    pub signing_public_key_hex: String,
    pub signing_private_key_hex: Option<String>,
    pub message_key_iteration: u32,
    pub message_key_seed_hex: String,
    pub encoded_hex: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct SignalSenderKeyRecordUnknownFieldFixture {
    pub name: String,
    pub key_id: u32,
    pub chain_key_hex: String,
    pub chain_iteration: u32,
    pub signing_public_key_hex: String,
    pub signing_private_key_hex: Option<String>,
    pub message_key_iteration: u32,
    pub message_key_seed_hex: String,
    pub encoded_hex: String,
    pub canonical_encoded_hex: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct SignalSenderKeyRecordInvalidSigningKeyFixture {
    pub name: String,
    pub key_id: u32,
    pub chain_key_hex: String,
    pub chain_iteration: u32,
    pub signing_public_key_hex: String,
    pub signing_private_key_hex: String,
    pub message_key_iteration: u32,
    pub message_key_seed_hex: String,
    pub expected_error: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct SignalSenderKeyRecordInvalidStateFixture {
    pub name: String,
    pub key_id: u32,
    pub chain_key_hex: String,
    pub chain_iteration: u32,
    pub signing_public_key_hex: String,
    pub signing_private_key_hex: Option<String>,
    pub message_key_iteration: u32,
    pub message_key_seed_hex: String,
    pub second_message_key_iteration: Option<u32>,
    pub second_message_key_seed_hex: Option<String>,
    pub duplicate_state: Option<bool>,
    pub expected_error: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct SignalSenderKeyRecordInvalidWireFixture {
    pub name: String,
    pub encoded_hex: String,
    pub expected_error: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct SignalSenderKeyRecordMessageFixture {
    pub name: String,
    pub key_id: u32,
    pub chain_key_hex: String,
    pub chain_iteration: u32,
    pub signing_public_key_hex: String,
    pub signing_private_key_hex: String,
    pub plaintext_hex: String,
    pub ciphertext_hex: String,
    pub sender_record_hex: String,
    pub receiver_record_before_reject_hex: String,
    pub receiver_record_hex: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct SignalSenderKeyMessageInvalidWireFixture {
    pub name: String,
    pub encoded_hex: String,
    pub expected_error: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct SignalSenderKeyMessageUnknownFieldFixture {
    pub name: String,
    pub key_id: u32,
    pub iteration: u32,
    pub ciphertext_hex: String,
    pub signature_hex: String,
    pub encoded_hex: String,
    pub canonical_encoded_hex: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct SignalSenderKeyMessageInvalidSignatureFixture {
    pub name: String,
    pub encoded_hex: String,
    pub signing_public_key_hex: String,
    pub expected_error: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct SignalSenderKeyRecordFarFutureFixture {
    pub name: String,
    pub key_id: u32,
    pub chain_key_hex: String,
    pub chain_iteration: u32,
    pub signing_public_key_hex: String,
    pub signing_private_key_hex: String,
    pub plaintext_hex: String,
    pub far_future_iteration: u32,
    pub far_future_ciphertext_hex: String,
    pub ciphertext_hex: String,
    pub sender_record_hex: String,
    pub receiver_record_before_reject_hex: String,
    pub receiver_record_hex: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct SignalSenderKeyRecordMultiStateDecryptFixture {
    pub name: String,
    pub key_id: u32,
    pub old_chain_key_hex: String,
    pub old_chain_iteration: u32,
    pub old_signing_public_key_hex: String,
    pub old_signing_private_key_hex: String,
    pub replacement_chain_key_hex: String,
    pub replacement_chain_iteration: u32,
    pub replacement_signing_public_key_hex: String,
    pub replacement_signing_private_key_hex: String,
    pub old_plaintext_hex: String,
    pub replacement_plaintext_hex: String,
    pub old_ciphertext_hex: String,
    pub replacement_ciphertext_hex: String,
    pub invalid_signature_error: String,
    pub failed_decrypt_error: String,
    pub far_future_iteration: u32,
    pub far_future_error: String,
    pub replay_error: String,
    pub receiver_record_before_reject_hex: String,
    pub receiver_record_after_old_hex: String,
    pub receiver_record_after_replacement_hex: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct SignalSenderKeyRecordOutOfOrderFixture {
    pub name: String,
    pub key_id: u32,
    pub chain_key_hex: String,
    pub chain_iteration: u32,
    pub signing_public_key_hex: String,
    pub signing_private_key_hex: String,
    pub first_plaintext_hex: String,
    pub second_plaintext_hex: String,
    pub tampered_first_ciphertext_hex: Option<String>,
    pub expected_tamper_error: Option<String>,
    pub invalid_signature_first_message_hex: Option<String>,
    pub expected_invalid_signature_error: Option<String>,
    pub receiver_record_after_invalid_signature_hex: Option<String>,
    #[serde(default)]
    pub expected_replay_error: Option<String>,
    pub receiver_record_before_reject_hex: String,
    pub first_ciphertext_hex: String,
    pub second_ciphertext_hex: String,
    pub sender_record_hex: String,
    pub receiver_record_after_second_hex: String,
    pub receiver_record_after_first_hex: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct SignalWhisperMessageFixture {
    pub name: String,
    pub ephemeral_key_hex: String,
    pub counter: u32,
    pub previous_counter: u32,
    pub ciphertext_hex: String,
    pub encoded_hex: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct SignalWhisperMessageMissingPreviousCounterFixture {
    pub name: String,
    pub ephemeral_key_hex: String,
    pub counter: u32,
    pub ciphertext_hex: String,
    pub encoded_hex: String,
    pub canonical_encoded_hex: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct SignalWhisperMessageUnknownFieldFixture {
    pub name: String,
    pub ephemeral_key_hex: String,
    pub counter: u32,
    pub previous_counter: u32,
    pub ciphertext_hex: String,
    pub encoded_hex: String,
    pub canonical_encoded_hex: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct SignalWhisperInvalidWireFixture {
    pub name: String,
    pub encoded_hex: String,
    pub expected_error: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct BinaryNodeFixture {
    pub name: String,
    pub encoded_hex: String,
    pub node: FixtureNode,
}

impl BinaryNodeFixture {
    pub fn encoded_bytes(&self) -> Result<Bytes, FixtureError> {
        decode_hex(&self.encoded_hex)
    }

    pub fn binary_node(&self) -> Result<BinaryNode, FixtureError> {
        self.node.clone().into_binary_node()
    }
}

pub fn decode_fixture_hex(value: &str) -> Result<Bytes, FixtureError> {
    decode_hex(value)
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct FixtureNode {
    pub tag: String,
    #[serde(default)]
    pub attrs: BTreeMap<String, String>,
    #[serde(default)]
    pub content: Option<FixtureContent>,
}

impl FixtureNode {
    pub fn into_binary_node(self) -> Result<BinaryNode, FixtureError> {
        let mut node = BinaryNode::new(self.tag);
        node.attrs = self.attrs;
        if let Some(content) = self.content {
            node.content = Some(content.into_binary_node_content()?);
        }
        Ok(node)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(untagged)]
pub enum FixtureContent {
    Nodes(Vec<FixtureNode>),
    Text { text: String },
    Bytes { bytes_hex: String },
}

impl FixtureContent {
    pub fn into_binary_node_content(self) -> Result<wa_binary::BinaryNodeContent, FixtureError> {
        Ok(match self {
            Self::Nodes(nodes) => {
                let nodes = nodes
                    .into_iter()
                    .map(FixtureNode::into_binary_node)
                    .collect::<Result<Vec<_>, _>>()?;
                wa_binary::BinaryNodeContent::Nodes(nodes)
            }
            Self::Text { text } => wa_binary::BinaryNodeContent::Text(text),
            Self::Bytes { bytes_hex } => {
                wa_binary::BinaryNodeContent::Bytes(decode_hex(&bytes_hex)?)
            }
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum FixtureError {
    #[error("fixture io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("fixture json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("hex string has odd length")]
    OddHexLength,
    #[error("invalid hex byte at index {index}: {value}")]
    InvalidHex { index: usize, value: String },
}

fn decode_hex(value: &str) -> Result<Bytes, FixtureError> {
    if !value.len().is_multiple_of(2) {
        return Err(FixtureError::OddHexLength);
    }
    let mut bytes = Vec::with_capacity(value.len() / 2);
    for index in (0..value.len()).step_by(2) {
        let pair = &value[index..index + 2];
        let byte = u8::from_str_radix(pair, 16).map_err(|_| FixtureError::InvalidHex {
            index,
            value: pair.to_owned(),
        })?;
        bytes.push(byte);
    }
    Ok(Bytes::from(bytes))
}
