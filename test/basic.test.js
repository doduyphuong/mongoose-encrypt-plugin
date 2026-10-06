const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const db = require('./helpers/db');
const { buildModel } = require('./helpers/models');

const sample = { name: 'A', email: 'a@example.com', phone: '0977777777', address: 'Ho Chi Minh City' };

describe('basic encryption (default options)', () => {
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
            assert.match(raw[field], /^[0-9a-f]+$/);
            assert.ok(raw.hashField[field], `hashField.${field} missing`);
            assert.match(raw.ivField[field], /^[0-9a-f]{32}$/);
        }
        assert.equal(raw.name, sample.name);
    });

    it('returns decrypted values from create()', async () => {
        const doc = await Model.create({ ...sample, email: 'create@example.com' });
        assert.equal(doc.email, 'create@example.com');
        assert.equal(doc.phone, sample.phone);
    });

    it('decrypts on find() and findById()', async () => {
        const created = await Model.create({ ...sample, email: 'find@example.com' });
        const found = await Model.findById(created._id);
        assert.equal(found.email, 'find@example.com');
        assert.equal(found.address, sample.address);
    });

    it('finds by equality on an encrypted field', async () => {
        await Model.create({ ...sample, name: 'Eq', email: 'eq@example.com' });
        const found = await Model.find({ email: 'eq@example.com' });
        assert.equal(found.length, 1);
        assert.equal(found[0].name, 'Eq');
    });

    it('encrypts values written with findOneAndUpdate + $set', async () => {
        const created = await Model.create({ ...sample, email: 'upd@example.com' });
        const updated = await Model.findOneAndUpdate({ _id: created._id }, { $set: { phone: '0900000000' } }, { new: true });
        assert.equal(updated.phone, '0900000000');

        const raw = await Model.collection.findOne({ _id: created._id });
        assert.notEqual(raw.phone, '0900000000');
        const byPhone = await Model.find({ phone: '0900000000' });
        assert.equal(byPhone.length, 1);
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

    it('decrypts aggregate() results', async () => {
        await Model.create({ ...sample, name: 'Agg', email: 'agg@example.com' });
        const rows = await Model.aggregate([{ $match: { name: 'Agg' } }]);
        assert.equal(rows.length, 1);
        assert.equal(rows[0].email, 'agg@example.com');
        assert.equal(rows[0].hashField, undefined);
    });

    it('toJSON() hides hashField and ivField', async () => {
        const created = await Model.create({ ...sample, email: 'json@example.com' });
        const json = (await Model.findById(created._id)).toJSON();
        assert.equal(json.hashField, undefined);
        assert.equal(json.ivField, undefined);
        assert.equal(json.email, 'json@example.com');
    });

    it('re-saving a legacy plaintext document encrypts it', async () => {
        const { insertedId } = await Model.collection.insertOne({ name: 'Legacy', email: 'legacy@example.com', phone: '', address: '' });
        const loaded = await Model.findById(insertedId);
        loaded.name = 'Legacy migrated';
        await loaded.save();

        const raw = await Model.collection.findOne({ _id: insertedId });
        assert.notEqual(raw.email, 'legacy@example.com');
        assert.ok(raw.hashField.email);
        assert.equal((await Model.findById(insertedId)).email, 'legacy@example.com');
    });

    it('insertMany() encrypts every document and returns decrypted values', async () => {
        const docs = await Model.insertMany([
            { ...sample, name: 'Many 1', email: 'many1@example.com' },
            { ...sample, name: 'Many 2', email: 'many2@example.com', phone: '' },
        ]);

        assert.equal(docs.length, 2);
        assert.equal(docs[0].email, 'many1@example.com');
        assert.equal(docs[1].email, 'many2@example.com');
        assert.equal(docs[1].phone, '');

        const raws = await Model.collection.find({ _id: { $in: docs.map(d => d._id) } }).sort({ name: 1 }).toArray();
        assert.notEqual(raws[0].email, 'many1@example.com');
        assert.notEqual(raws[0].hashField.email, raws[1].hashField.email, 'each document has its own hash');
        assert.equal(raws[1].hashField.phone, undefined, 'empty value is not hashed');

        const found = await Model.find({ email: 'many2@example.com' });
        assert.equal(found.length, 1);
        assert.equal(found[0].name, 'Many 2');
    });

    it('insertMany() with a single object and with an empty array', async () => {
        const single = await Model.insertMany({ ...sample, name: 'Single', email: 'single@example.com' });
        assert.equal(single.length, 1);
        assert.equal(single[0].email, 'single@example.com');

        const none = await Model.insertMany([]);
        assert.deepEqual(none, []);
    });

    it('insertMany() reports the original validation error', async () => {
        await assert.rejects(
            Model.insertMany([{ email: 'noname@example.com' }]),
            (err) => err.name === 'ValidationError' && /name/.test(err.message),
        );
    });
});
