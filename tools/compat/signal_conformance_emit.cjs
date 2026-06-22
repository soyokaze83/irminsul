// Emit authoritative libsignal conformance fixtures for the Rust repo to verify against.
// Produces: Bob's full key material, Alice->Bob PreKeyWhisperMessage, an established-session
// WhisperMessage, and expected plaintexts. All hex. The Rust provider must be able to decrypt
// these (proving wire+crypto compatibility with WhatsApp/Baileys).
const { keyhelper, ProtocolAddress, SessionBuilder, SessionCipher, SessionRecord } = require('libsignal');
const fs = require('fs');
const H = (b) => Buffer.from(b, typeof b === 'string' ? 'binary' : undefined).toString('hex');

function makeStore(identity, regId, prekeys = {}, signed = {}) {
  const sessions = {};
  return {
    getOurIdentity: async () => identity,
    getOurRegistrationId: async () => regId,
    isTrustedIdentity: async () => true,
    loadPreKey: async (id) => prekeys[id],
    removePreKey: async (id) => { delete prekeys[id]; },
    loadSignedPreKey: async (id) => signed[id],
    loadSession: async (a) => { const r = sessions[a]; return r ? SessionRecord.deserialize(r) : undefined; },
    storeSession: async (a, r) => { sessions[a] = r.serialize(); },
    saveIdentity: async () => true,
    _sessions: sessions,
  };
}

(async () => {
  const bobIdentity = keyhelper.generateIdentityKeyPair();
  const bobReg = keyhelper.generateRegistrationId();
  const bobPre = keyhelper.generatePreKey(31337);
  const bobSpk = keyhelper.generateSignedPreKey(bobIdentity, 22);
  const bobStore = makeStore(bobIdentity, bobReg, { 31337: bobPre.keyPair }, { 22: bobSpk.keyPair });

  const aliceIdentity = keyhelper.generateIdentityKeyPair();
  const aliceReg = keyhelper.generateRegistrationId();
  const aliceStore = makeStore(aliceIdentity, aliceReg);

  const bobAddr = new ProtocolAddress('bob', 1);
  const aliceAddr = new ProtocolAddress('alice', 1);

  await new SessionBuilder(aliceStore, bobAddr).initOutgoing({
    identityKey: bobIdentity.pubKey,
    registrationId: bobReg,
    preKey: { keyId: bobPre.keyId, publicKey: bobPre.keyPair.pubKey },
    signedPreKey: { keyId: bobSpk.keyId, publicKey: bobSpk.keyPair.pubKey, signature: bobSpk.signature },
  });

  const m1 = await new SessionCipher(aliceStore, bobAddr).encrypt(Buffer.from('hello bob'));
  // establish bob's session so we can also emit a plain WhisperMessage
  const bobCipher = new SessionCipher(bobStore, aliceAddr);
  await bobCipher.decryptPreKeyWhisperMessage(Buffer.from(m1.body, 'binary'));
  const m2 = await new SessionCipher(bobStore, aliceAddr).encrypt(Buffer.from('hi alice from bob'));
  // alice decrypts m2 to advance, then sends a plain whisper m3 alice->bob
  await new SessionCipher(aliceStore, bobAddr).decryptWhisperMessage(Buffer.from(m2.body, 'binary'));
  const m3 = await new SessionCipher(aliceStore, bobAddr).encrypt(Buffer.from('second from alice'));

  const fx = {
    note: 'Authoritative libsignal (Baileys) conformance vectors. Rust provider must decrypt these.',
    bob: {
      registrationId: bobReg,
      identityKeyPub: H(bobIdentity.pubKey), identityKeyPriv: H(bobIdentity.privKey),
      preKeyId: bobPre.keyId, preKeyPub: H(bobPre.keyPair.pubKey), preKeyPriv: H(bobPre.keyPair.privKey),
      signedPreKeyId: bobSpk.keyId, signedPreKeyPub: H(bobSpk.keyPair.pubKey), signedPreKeyPriv: H(bobSpk.keyPair.privKey),
      signedPreKeySig: H(bobSpk.signature),
    },
    alice: { registrationId: aliceReg, identityKeyPub: H(aliceIdentity.pubKey) },
    vectors: [
      { dir: 'alice->bob', kind: 'prekey', type: m1.type, body: H(m1.body), plaintext: 'hello bob' },
      { dir: 'alice->bob', kind: 'whisper', type: m3.type, body: H(m3.body), plaintext: 'second from alice' },
    ],
    bobToAlice: { dir: 'bob->alice', kind: 'whisper', type: m2.type, body: H(m2.body), plaintext: 'hi alice from bob' },
  };
  const out = process.argv[2] || '/tmp/sigoracle/signal_conformance.json';
  fs.writeFileSync(out, JSON.stringify(fx, null, 2));
  console.log('wrote', out);
  console.log('m1(prekey) type', m1.type, 'firstByte', '0x' + Buffer.from(m1.body,'binary')[0].toString(16));
  console.log('m3(whisper) type', m3.type, 'firstByte', '0x' + Buffer.from(m3.body,'binary')[0].toString(16));
})().catch(e => { console.error('ERR', e); process.exit(1); });
