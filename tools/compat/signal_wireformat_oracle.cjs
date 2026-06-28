// Authoritative oracle using `libsignal` (the exact pkg Baileys/WhatsApp use).
const { keyhelper, ProtocolAddress, SessionBuilder, SessionCipher, SessionRecord } = require('libsignal');
const hex = (b) => Buffer.from(b, typeof b === 'string' ? 'binary' : undefined).toString('hex');

function makeStore(identity, regId, prekeys = {}, signed = {}) {
  const sessions = {};
  return {
    getOurIdentity: async () => identity,
    getOurRegistrationId: async () => regId,
    isTrustedIdentity: async () => true,
    loadPreKey: async (id) => prekeys[id],
    removePreKey: async (id) => { delete prekeys[id]; },
    loadSignedPreKey: async (id) => signed[id],
    loadSession: async (addr) => { const r = sessions[addr]; return r ? SessionRecord.deserialize(r) : undefined; },
    storeSession: async (addr, rec) => { sessions[addr] = rec.serialize(); },
    saveIdentity: async () => true,
  };
}

(async () => {
  // Bob
  const bobIdentity = keyhelper.generateIdentityKeyPair();
  const bobReg = keyhelper.generateRegistrationId();
  const bobPre = keyhelper.generatePreKey(31337);
  const bobSpk = keyhelper.generateSignedPreKey(bobIdentity, 22);
  const bobStore = makeStore(bobIdentity, bobReg,
    { 31337: bobPre.keyPair },
    { 22: bobSpk.keyPair });

  // Alice
  const aliceIdentity = keyhelper.generateIdentityKeyPair();
  const aliceReg = keyhelper.generateRegistrationId();
  const aliceStore = makeStore(aliceIdentity, aliceReg);

  const bobAddr = new ProtocolAddress('bob', 1);
  const aliceAddr = new ProtocolAddress('alice', 1);

  const bundle = {
    identityKey: bobIdentity.pubKey,
    registrationId: bobReg,
    preKey: { keyId: bobPre.keyId, publicKey: bobPre.keyPair.pubKey },
    signedPreKey: { keyId: bobSpk.keyId, publicKey: bobSpk.keyPair.pubKey, signature: bobSpk.signature },
  };

  await new SessionBuilder(aliceStore, bobAddr).initOutgoing(bundle);

  // Alice -> Bob : PreKeyWhisperMessage (type 3)
  const ct1 = await new SessionCipher(aliceStore, bobAddr).encrypt(Buffer.from('hello bob'));
  const b1 = Buffer.from(ct1.body, 'binary');
  console.log('=== Alice->Bob msg1 (PreKeyWhisperMessage) ===');
  console.log('type:', ct1.type, 'len:', b1.length, 'firstByte: 0x' + b1[0].toString(16));
  console.log('hex:', b1.toString('hex'));

  // Bob decrypts to establish his session
  const bobCipher = new SessionCipher(bobStore, aliceAddr);
  const pt = await bobCipher.decryptPreKeyWhisperMessage(b1);
  console.log('bob decrypted:', Buffer.from(pt).toString());

  // Bob -> Alice : WhisperMessage (type 1)
  const ct2 = await new SessionCipher(bobStore, aliceAddr).encrypt(Buffer.from('hi alice'));
  const b2 = Buffer.from(ct2.body, 'binary');
  console.log('\n=== Bob->Alice (WhisperMessage type 1) ===');
  console.log('type:', ct2.type, 'len:', b2.length, 'firstByte: 0x' + b2[0].toString(16));
  console.log('hex:', b2.toString('hex'));
  console.log('version_byte: 0x' + b2[0].toString(16), '(expect 0x33 = (3<<4)|3)');
  console.log('last8_MAC:', b2.slice(b2.length - 8).toString('hex'));
  console.log('middle_protobuf:', b2.slice(1, b2.length - 8).toString('hex'));
})().catch(e => { console.error('ERR:', e); process.exit(1); });
