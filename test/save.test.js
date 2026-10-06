const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const db = require('./helpers/db');
const { buildModel, sample } = require('./helpers/models');
const { pending } = require('./helpers/pending');

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

    it('stores ciphertext, hash and iv in the database', async () => {
        const doc = await Model.create(sample);
        const raw = await Model.collection.findOne({ _id: doc._id });

        for (const field of ['email', 'phone', 'address']) {
            assert.notEqual(raw[field], sample[field], `${field} must not be stored in plaintext`);
            assert.ok(raw.hashField[field], `hashField.${field} missing`);
        }
        assert.equal(raw.name, sample.name);
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

    it('#2 the search hash is keyed (not a plain SHA-256 of the value)', pending('GD 1'), async () => {
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

    it('#4 rejects a second document with the same email', pending('GD 1'), async () => {
        await Model.create({ ...sample, email: 'dup@example.com' });
        await assert.rejects(Model.create({ ...sample, email: 'dup@example.com' }), /duplicate key|E11000/);
    });
});
