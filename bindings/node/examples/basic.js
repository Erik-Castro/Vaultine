const { Vaultine } = require('../lib/index.js');

// Create in-memory vault
const vault = new Vaultine();
console.log('dbVersion:', vault.dbVersion());

// Run migration (creates tables)
vault.dbMigrate();
console.log('dbVersion after migrate:', vault.dbVersion());

// Register a user
vault.userRegister('alice', 'secret123');
console.log('Registered alice');

// Authenticate
const ok = vault.userAuthenticate('alice', 'secret123');
console.log('Auth valid:', ok);

const bad = vault.userAuthenticate('alice', 'wrong');
console.log('Auth wrong password:', bad);

// Store a secret
const privateKey = Buffer.from('my-super-secret-key-material');
vault.secretStore('alice', privateKey, null, 'mykey', 'My first key');
console.log('Stored secret');

// Retrieve the secret
const result = vault.secretGet('alice', 'mykey');
console.log('Retrieved private key:', result.privateKey.toString());

// List secrets
const list = vault.secretList('alice');
console.log('Secrets:', list.map(e => `${e.name}: ${e.description}`));

// Audit log
const audit = vault.auditLogQuery({ limit: 5 });
console.log('Recent audit entries:', audit.length);

// Cache stats
console.log('Cache stats:', vault.cacheStats());

// Export
const exported = vault.export('json', false);
console.log('Export length:', exported.length);

// Cleanup
vault.destroy();
console.log('\nDone!');
