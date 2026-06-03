const { Vaultine } = require('../lib/index.js');
const assert = require('node:assert');
const fs = require('node:fs');
const crypto = require('node:crypto');

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function randomKey(len = 32) {
  return crypto.randomBytes(len);
}

const TMPDIR = '/data/data/com.termux/files/usr/tmp';

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    passed++;
    console.log(`  PASS  ${name}`);
  } catch (e) {
    failed++;
    console.error(`  FAIL  ${name}: ${e.message}`);
  }
}

function expectError(fn, msgContains) {
  try {
    fn();
    throw new Error('Expected error but got success');
  } catch (e) {
    if (msgContains && !e.message.includes(msgContains)) {
      throw new Error(`Expected error containing "${msgContains}" but got "${e.message}"`);
    }
  }
}

// ---------------------------------------------------------------------------
// Setup
// ---------------------------------------------------------------------------
console.log('Vaultine Node.js test suite\n');

// 1) In-memory, no key
let vault;
test('create in-memory vault', () => {
  vault = new Vaultine();
  assert.ok(vault instanceof Vaultine);
});

test('dbMigrate succeeds', () => {
  vault.dbMigrate();
  const v = vault.dbVersion();
  assert.ok(v >= 1);
});

// 2) User registration & auth
test('userRegister creates user', () => {
  vault.userRegister('alice', 'secret123');
});

test('userAuthenticate returns true for valid creds', () => {
  const ok = vault.userAuthenticate('alice', 'secret123');
  assert.strictEqual(ok, true);
});

test('userAuthenticate returns false for bad password', () => {
  const ok = vault.userAuthenticate('alice', 'wrong');
  assert.strictEqual(ok, false);
});

test('userAuthenticate returns false for unknown user', () => {
  const ok = vault.userAuthenticate('nobody', 'x');
  assert.strictEqual(ok, false);
});

// 3) Secret store / get / list / delete
test('secretStore creates a secret', () => {
  const priv = Buffer.from('my-private-key-data');
  vault.secretStore('alice', priv, null, 'mykey', 'A test key');
});

test('secretGet retrieves private key', () => {
  const result = vault.secretGet('alice', 'mykey');
  assert.ok(Buffer.isBuffer(result.privateKey));
  assert.strictEqual(result.privateKey.toString(), 'my-private-key-data');
});

test('secretGet with public key', () => {
  const priv = Buffer.from('priv2');
  const pub = Buffer.from('pub2');
  vault.secretStore('alice', priv, pub, 'keypair', 'With public key');
  const result = vault.secretGet('alice', 'keypair');
  assert.strictEqual(result.privateKey.toString(), 'priv2');
  assert.strictEqual(result.publicKey.toString(), 'pub2');
});

test('secretList returns secrets', () => {
  const list = vault.secretList('alice');
  assert.ok(Array.isArray(list));
  const names = list.map(e => e.name);
  assert.ok(names.includes('mykey'));
  assert.ok(names.includes('keypair'));
  list.forEach(e => {
    assert.ok(typeof e.name === 'string');
    assert.ok(typeof e.updatedAt === 'string');
    assert.ok(typeof e.pubKeyLen === 'number');
  });
});

test('secretList returns description field', () => {
  const list = vault.secretList('alice');
  const mykey = list.find(e => e.name === 'mykey');
  assert.strictEqual(mykey.description, 'A test key');
  const kp = list.find(e => e.name === 'keypair');
  assert.strictEqual(kp.description, 'With public key');
});

test('secretDelete removes a secret', () => {
  vault.secretDelete('alice', 'mykey');
  const list = vault.secretList('alice');
  assert.ok(!list.find(e => e.name === 'mykey'));
});

test('secretGet after delete fails', () => {
  expectError(() => vault.secretGet('alice', 'mykey'), 'SSM_ERR_NOT_FOUND');
});

// 4) KEK rotation
test('kekRotate succeeds', () => {
  vault.kekRotate('alice');
});

test('secret still readable after KEK rotation', () => {
  const result = vault.secretGet('alice', 'keypair');
  assert.strictEqual(result.privateKey.toString(), 'priv2');
});

// 5) Cache stats
test('cacheStats returns valid structure', () => {
  const s = vault.cacheStats();
  assert.ok(typeof s.totalEntries === 'number');
  assert.ok(typeof s.validEntries === 'number');
  assert.ok(typeof s.hitCount === 'number');
  assert.ok(typeof s.missCount === 'number');
});

// 6) Audit log
test('auditLogQuery returns entries', () => {
  const entries = vault.auditLogQuery({ limit: 10, offset: 0 });
  assert.ok(Array.isArray(entries));
  assert.ok(entries.length >= 4);
  entries.forEach(e => {
    assert.ok(typeof e.id === 'number');
    assert.ok(typeof e.username === 'string');
    assert.ok(typeof e.operation === 'string');
    assert.ok(typeof e.timestamp === 'string');
  });
});

test('auditLogQuery with username filter', () => {
  const entries = vault.auditLogQuery({ username: 'alice' });
  entries.forEach(e => assert.strictEqual(e.username, 'alice'));
});

// 7) Export
test('export produces JSON object', () => {
  const json = vault.export('json', false);
  const data = JSON.parse(json);
  assert.ok(data !== null && typeof data === 'object');
  assert.ok(Array.isArray(data.users));
  assert.ok(Array.isArray(data.secrets));
});

test('export with redact PII', () => {
  const json = vault.export('json', true);
  const data = JSON.parse(json);
  assert.ok(data !== null && typeof data === 'object');
});

// 8) User change password
test('userChangePassword succeeds', () => {
  vault.userChangePassword('alice', 'secret123', 'newsecret456');
  const ok = vault.userAuthenticate('alice', 'newsecret456');
  assert.strictEqual(ok, true);
  const old = vault.userAuthenticate('alice', 'secret123');
  assert.strictEqual(old, false);
});

// 9) User delete
test('userDelete removes user', () => {
  vault.userRegister('bob', 'bobpass');
  vault.userDelete('bob', 'bobpass');
  const ok = vault.userAuthenticate('bob', 'bobpass');
  assert.strictEqual(ok, false);
});

// 10) Backup / restore (requires file-based DB)
test('backupCreate + backupRestore round-trip', () => {
  const dbPath = `${TMPDIR}/vaultine-node-test-backup2.db`;
  const encPath = `${TMPDIR}/vaultine-node-test-backup2.db.enc`;

  // Clean any leftover files (including WAL/SHM)
  const cleanPath = (p) => {
    for (const ext of ['', '-wal', '-shm']) {
      try { fs.unlinkSync(p + ext); } catch (_) {}
    }
  };
  cleanPath(dbPath);
  cleanPath(dbPath + '.restored');
  try { fs.unlinkSync(encPath); } catch (_) {}

  const key = randomKey(32);
  const v1 = new Vaultine(dbPath);
  v1.userRegister('carol', 'carolpass');
  const priv = Buffer.from('backup-secret');
  v1.secretStore('carol', priv, null, 'bk1', 'backup test');
  v1.backupCreate(encPath, key);

  const v2 = new Vaultine(dbPath + '.restored');
  v2.backupRestore(encPath, key);
  const result = v2.secretGet('carol', 'bk1');
  assert.strictEqual(result.privateKey.toString(), 'backup-secret');

  v1.destroy();
  v2.destroy();
  cleanPath(dbPath);
  cleanPath(dbPath + '.restored');
  try { fs.unlinkSync(encPath); } catch (_) {}
});

// 11) Error cases
test('double destroy is safe', () => {
  const v = new Vaultine();
  v.destroy();
  expectError(() => v.destroy());
});

// 12) Re-create after destroy
test('re-create after destroy', () => {
  const v = new Vaultine();
  v.dbMigrate();
  v.destroy();
});

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------
console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed > 0 ? 1 : 0);
