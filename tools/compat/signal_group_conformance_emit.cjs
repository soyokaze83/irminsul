// Emit authoritative libsignal GROUP (sender-key) conformance fixtures for the Rust
// repo to verify against. Produces a SenderKeyDistributionMessage and a SenderKeyMessage
// (group "skmsg" ciphertext) for a fresh sender key, plus the expected plaintext. All hex.
//
// The `libsignal` JS package Baileys/WhatsApp use ships the 1:1 primitives (curve, crypto,
// keyhelper) but vendors its GROUP API separately (the `WASignalGroup` module). This emitter
// reconstructs that exact legacy sender-key wire format using libsignal's own primitives
// (curve.calculateSignature == XEdDSA, crypto.deriveSecrets == HKDF, crypto.encrypt == AES-CBC),
// so the produced bytes are byte-identical to what Baileys/WhatsApp emit. The Rust provider
// must PROCESS the distribution and DECRYPT the SenderKeyMessage.
//
// Wire format (legacy libsignal sender key, what WhatsApp/Baileys use):
//   SenderKeyDistributionMessage = versionByte || protobuf{1:id, 2:iteration, 3:chainKey, 4:signingKey(0x05+32)}
//   SenderKeyMessage             = versionByte || protobuf{1:id, 2:iteration, 3:ciphertext} || signature(64)
//   versionByte = (3<<4)|3 = 0x33  (CURRENT_VERSION nibble in both halves)
//   signature = Curve.calculateSignature(signingPrivKey, versionByte||protobuf)  (XEdDSA, 64 bytes)
//   senderChainKey ratchet: messageKeySeed = HMAC-SHA256(chainKey, [0x01]); nextChainKey = HMAC-SHA256(chainKey, [0x02])
//   senderMessageKey derive: HKDF(seed, salt=ZERO32, info="WhisperGroup", 48) -> iv=out[0..16], cipherKey=out[16..48]
//   GroupCipher.encrypt: uses CURRENT chainKey's messageKey (iteration = chainKey.iteration), THEN advances.
//     => fresh key created at iteration 0: first SenderKeyMessage carries iteration 0.

const { curve, crypto: sigCrypto, keyhelper } = require('libsignal');
const nodeCrypto = require('crypto');
const fs = require('fs');

const H = (b) => Buffer.from(b).toString('hex');
const CURRENT_VERSION = 3;
const VERSION_BYTE = (CURRENT_VERSION << 4) | CURRENT_VERSION; // 0x33

// --- minimal protobuf encoding (varints + length-delimited) ---
function varint(n) {
  const out = [];
  let v = n >>> 0;
  do {
    let b = v & 0x7f;
    v >>>= 7;
    if (v) b |= 0x80;
    out.push(b);
  } while (v);
  return Buffer.from(out);
}
function tag(field, wire) { return varint((field << 3) | wire); }
function fieldVarint(field, n) { return Buffer.concat([tag(field, 0), varint(n)]); }
function fieldBytes(field, buf) { return Buffer.concat([tag(field, 2), varint(buf.length), buf]); }

// --- legacy senderkey ratchet primitives ---
function hmac(key, data) {
  return nodeCrypto.createHmac('sha256', key).update(data).digest();
}
const MESSAGE_KEY_SEED = Buffer.from([0x01]);
const CHAIN_KEY_SEED = Buffer.from([0x02]);

function deriveMessageKeySeed(chainKey) { return hmac(chainKey, MESSAGE_KEY_SEED); }
function nextChainKey(chainKey) { return hmac(chainKey, CHAIN_KEY_SEED); }

function deriveSenderMessageKey(seed) {
  // libsignal: HKDFv3.deriveSecrets(seed, "WhisperGroup", 48), salt = 32 zero bytes.
  const salt = Buffer.alloc(32, 0);
  const info = Buffer.from('WhisperGroup');
  // crypto.deriveSecrets returns 32-byte chunks; 2 chunks = 64 bytes, take first 48.
  const chunks = sigCrypto.deriveSecrets(seed, salt, info, 2);
  const derivative = Buffer.concat(chunks).slice(0, 48);
  return { iv: derivative.slice(0, 16), cipherKey: derivative.slice(16, 48) };
}

(async () => {
  const groupId = 'group-conformance@g.us';
  const senderJid = 'alice:1@s.whatsapp.net';
  const plaintext = 'group hello';

  // Alice creates a brand-new sender key (GroupSessionBuilder.create).
  const keyId = keyhelper.generateRegistrationId() & 0x7fffffff; // any u32-ish id
  const iteration0 = 0;
  const chainKey0 = nodeCrypto.randomBytes(32);
  const signing = curve.generateKeyPair(); // {pubKey: 0x05+32, privKey: 32}

  // SenderKeyDistributionMessage (versionByte || protobuf{id,iteration,chainKey,signingKey}).
  const sdkmProto = Buffer.concat([
    fieldVarint(1, keyId),
    fieldVarint(2, iteration0),
    fieldBytes(3, chainKey0),
    fieldBytes(4, signing.pubKey), // 33 bytes (0x05-prefixed)
  ]);
  const distribution = Buffer.concat([Buffer.from([VERSION_BYTE]), sdkmProto]);

  // GroupCipher.encrypt: use CURRENT chainKey (iteration 0), then advance.
  const msgIteration = iteration0; // first message off a fresh key => iteration 0
  const seed = deriveMessageKeySeed(chainKey0);
  const { iv, cipherKey } = deriveSenderMessageKey(seed);
  const ciphertext = sigCrypto.encrypt(cipherKey, Buffer.from(plaintext), iv);

  // SenderKeyMessage = versionByte || protobuf{id,iteration,ciphertext} || signature(64).
  const skmProto = Buffer.concat([
    fieldVarint(1, keyId),
    fieldVarint(2, msgIteration),
    fieldBytes(3, ciphertext),
  ]);
  const signedPayload = Buffer.concat([Buffer.from([VERSION_BYTE]), skmProto]);
  const signature = curve.calculateSignature(signing.privKey, signedPayload);
  const skmsg = Buffer.concat([signedPayload, signature]);

  // Self-verify the signature so a broken fixture fails here, not in Rust.
  if (!curve.verifySignature(signing.pubKey, signedPayload, signature)) {
    throw new Error('self-check: signature did not verify');
  }
  // Self-verify decryption round-trips.
  const back = sigCrypto.decrypt(cipherKey, ciphertext, iv).toString();
  if (back !== plaintext) {
    throw new Error(`self-check: decrypt mismatch: ${back}`);
  }

  const fx = {
    note: 'Authoritative libsignal (Baileys/WhatsApp legacy sender-key) GROUP conformance vectors. '
      + 'Rust provider must process the distribution and decrypt the SenderKeyMessage.',
    groupId,
    senderJid,
    keyId,
    distribution: H(distribution),
    senderKeyMessage: {
      type: 'skmsg',
      firstByte: '0x' + skmsg[0].toString(16),
      iteration: msgIteration,
      body: H(skmsg),
    },
    signingKeyPub: H(signing.pubKey),
    plaintext,
  };

  const out = process.argv[2] || '/tmp/sigoracle/signal_group_conformance.json';
  fs.writeFileSync(out, JSON.stringify(fx, null, 2));
  console.log('wrote', out);
  console.log('distribution firstByte', '0x' + distribution[0].toString(16), 'len', distribution.length);
  console.log('skmsg firstByte', '0x' + skmsg[0].toString(16), 'iteration', msgIteration, 'len', skmsg.length);
})().catch((e) => { console.error('ERR', e); process.exit(1); });
