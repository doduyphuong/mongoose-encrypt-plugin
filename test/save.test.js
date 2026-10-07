const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const db = require('./helpers/db');
const { buildModel, sample } = require('./helpers/models');

const sha256 = (value) => crypto.createHash('sha256').update(value).digest('base64');

describe('save / create', () => {
    let Model;

    before(async () => {
        await db.connect();
        Model = buildModel();
    });

    after(async () => {
        await db.disconnect();
    });

    it('stores AES-256-GCM ciphertext and a search hash in the database', async () => {
        const doc = await Model.create(sample);
        const raw = await Model.collection.findOne({ _id: doc._id });

        for (const field of ['email', 'phone', 'address']) {
            assert.match(raw[field], /^v2:[0-9a-f]{24}:[0-9a-f]{32}:[0-9a-f]+$/, `${field} must be stored as v2 ciphertext`);
            assert.ok(raw.hashField[field], `hashField.${field} missing`);
            assert.equal(raw.ivField?.[field], undefined, 'v2 values keep their iv inside the ciphertext');
        }
        assert.equal(raw.name, sample.name);
    });

    it('a loaded document has no modified paths and an unchanged save keeps the ciphertext', async () => {
        const created = await Model.create({ ...sample, email: 'clean@example.com' });
        const before = await Model.collection.findOne({ _id: created._id });

        const loaded = await Model.findById(created._id);
        assert.equal(loaded.email, 'clean@example.com');
        assert.deepEqual(loaded.modifiedPaths(), []);

        loaded.name = 'Clean renamed';
        await loaded.save();

        const after = await Model.collection.findOne({ _id: created._id });
        assert.equal(after.email, before.email, 'unchanged encrypted field is not rewritten');
        assert.equal(after.name, 'Clean renamed');
    });

    it('never encrypts an already encrypted value twice', async () => {
        const source = await Model.collection.findOne({}, { sort: { _id: 1 } });
        const copy = await Model.create({ name: 'Copy', email: source.email });
        const raw = await Model.collection.findOne({ _id: copy._id });

        assert.equal(raw.email, source.email);
        assert.equal(raw.hashField.email, source.hashField.email);
    });

    it('returns decrypted values from create()', async () => {
        const doc = await Model.create({ ...sample, email: 'create@example.com' });
        assert.equal(doc.email, 'create@example.com');
        assert.equal(doc.phone, sample.phone);
    });

    it('re-saving a loaded document keeps data readable', async () => {
        const created = await Model.create({ ...sample, email: 'resave@example.com' });
        const loaded = await Model.findById(created._id);
        loaded.name = 'Renamed';
        await loaded.save();

        const again = await Model.findById(created._id);
        assert.equal(again.name, 'Renamed');
        assert.equal(again.email, 'resave@example.com');
        assert.equal((await Model.find({ email: 'resave@example.com' })).length, 1);
    });

    it('re-saving a legacy plaintext document encrypts it', async () => {
        const { insertedId } = await Model.collection.insertOne({ name: 'Legacy', email: 'legacy@example.com', phone: '', address: '' });
        const loaded = await Model.findById(insertedId);
        loaded.name = 'Legacy migrated';
        await loaded.save();

        const raw = await Model.collection.findOne({ _id: insertedId });
        assert.notEqual(raw.email, 'legacy@example.com');
        assert.equal((await Model.findById(insertedId)).email, 'legacy@example.com');
    });

    it('clearing an encrypted field on save() removes its stale hash', async () => {
        const created = await Model.create({ ...sample, email: 'clear@example.com' });
        const loaded = await Model.findById(created._id);
        loaded.email = '';
        await loaded.save();

        assert.equal((await Model.find({ email: 'clear@example.com' })).length, 0);
    });

    it('#2 the search hash is keyed (not a plain SHA-256 of the value)', async () => {
        const doc = await Model.create({ ...sample, email: 'keyed@example.com' });
        const raw = await Model.collection.findOne({ _id: doc._id });
        assert.notEqual(raw.hashField.email, sha256('keyed@example.com'));
    });
});

describe('#4 unique encrypted fields', () => {
    let Model;

    before(async () => {
        await db.connect();
        Model = buildModel({ unique: ['email'] });
        await Model.init();
    });

    after(async () => {
        await db.disconnect();
    });

    it('#4 rejects a second document with the same email', async () => {
        await Model.create({ ...sample, email: 'dup@example.com' });
        await assert.rejects(Model.create({ ...sample, email: 'dup@example.com' }), /duplicate key|E11000/);
    });
});
