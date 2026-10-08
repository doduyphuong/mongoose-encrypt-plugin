const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const db = require('./helpers/db');
const { buildModel, SALT } = require('./helpers/models');
const { migrateV1, OptionsError } = require('../mongoose-encrypt');

/** A document exactly as plugin v1 stored it (AES-256-CTR, iv in ivField, unkeyed SHA-256 hash). */
function v1Document(name, values) {
    const doc = { name, phone: '', address: '', hashField: {}, ivField: {} };

    for (const [field, plain] of Object.entries(values)) {
        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv('aes-256-ctr', SALT, iv);
        doc[field] = Buffer.concat([cipher.update(plain), cipher.final()]).toString('hex');
        doc.hashField[field] = crypto.createHash('sha256').update(plain).digest('base64');
        doc.ivField[field] = iv.toString('hex');
    }

    return doc;
}

const names = (docs) => docs.map(d => d.name).sort();

describe('migration from v1', () => {
    let Model;

    before(async () => {
        await db.connect();
        Model = buildModel({ legacy: { salt: SALT } });
        await Model.collection.insertMany([
            v1Document('Old1', { email: 'old1@example.com', phone: '0911' }),
            v1Document('Old2', { email: 'old2@example.com' }),
            v1Document('Old3', { email: 'old3@example.com' }),
        ]);
        await Model.create({ name: 'New1', email: 'new1@example.com' });
    });

    after(async () => {
        await db.disconnect();
    });

    it('finds v1 and v2 documents by an encrypted field before the migration', async () => {
        assert.deepEqual(names(await Model.find({ email: 'old1@example.com' })), ['Old1']);
        assert.deepEqual(names(await Model.find({ email: { $in: ['old2@example.com', 'new1@example.com'] } })), ['New1', 'Old2']);
        assert.deepEqual(names(await Model.find({ email: { $ne: 'old3@example.com' } })), ['New1', 'Old1', 'Old2']);
        assert.equal((await Model.findOne({ phone: '0911' })).email, 'old1@example.com');
    });

    it('dryRun counts the documents without writing', async () => {
        const stats = await migrateV1(Model, { dryRun: true, batchSize: 2 });
        assert.equal(stats.scanned, 3);
        assert.equal(stats.migrated, 3);
        assert.deepEqual(stats.failed, []);
        assert.equal(await Model.collection.countDocuments({ ivField: { $exists: true } }), 3);
    });

    it('reports a document that cannot be decrypted and leaves it untouched', async () => {
        const broken = v1Document('Broken', { email: 'broken@example.com' });
        broken.ivField.email = 'zz';
        const { insertedId } = await Model.collection.insertOne(broken);

        const stats = await migrateV1(Model, { dryRun: true });
        assert.equal(stats.failed.length, 1);
        assert.equal(String(stats.failed[0]._id), String(insertedId));
        assert.equal(stats.failed[0].field, 'email');

        await Model.collection.deleteOne({ _id: insertedId });
    });

    it('migrates every v1 document in batches and is safe to run again', async () => {
        const progress = [];
        const stats = await migrateV1(Model, { batchSize: 2, onProgress: (s) => progress.push(s.scanned) });

        assert.equal(stats.migrated, 3);
        assert.deepEqual(progress, [2, 3]);
        assert.equal(await Model.collection.countDocuments({ ivField: { $exists: true } }), 0);

        const raw = await Model.collection.findOne({ name: 'Old1' });
        assert.match(raw.email, /^v2:/);
        assert.match(raw.phone, /^v2:/);
        assert.notEqual(raw.hashField.email, crypto.createHash('sha256').update('old1@example.com').digest('base64'));

        const again = await Model.migrateEncryption();
        assert.equal(again.migrated, 0);
    });

    it('migrated documents are readable and searchable without the legacy option', async () => {
        const Plain = buildModel();
        const Migrated = Plain.db.model(`${Plain.modelName}Migrated`, Plain.schema, Model.collection.collectionName);

        const doc = await Migrated.findOne({ email: 'old2@example.com' });
        assert.equal(doc.name, 'Old2');
        assert.equal(doc.email, 'old2@example.com');
    });

    it('needs the legacy option (or includePlaintext)', async () => {
        const Plain = buildModel();
        await assert.rejects(migrateV1(Plain), OptionsError);
        assert.throws(() => migrateV1({}), OptionsError);
    });
});

describe('migration of plaintext values (includePlaintext)', () => {
    let Model;

    before(async () => {
        await db.connect();
        Model = buildModel({ haveDataNotEncrypt: true });
        await Model.collection.insertOne({ name: 'Plain', email: 'plain@example.com', phone: '', address: '' });
    });

    after(async () => {
        await db.disconnect();
    });

    it('encrypts values still stored in plaintext', async () => {
        const stats = await migrateV1(Model, { includePlaintext: true });
        assert.equal(stats.migrated, 1);

        const raw = await Model.collection.findOne({ name: 'Plain' });
        assert.match(raw.email, /^v2:/);
        assert.equal(raw.phone, '');
        assert.equal((await Model.findOne({ email: 'plain@example.com' })).name, 'Plain');
        assert.equal((await migrateV1(Model, { includePlaintext: true })).migrated, 0);
    });
});
