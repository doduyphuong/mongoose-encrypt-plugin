const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const db = require('./helpers/db');
const { buildModel } = require('./helpers/models');
const { userContextStore } = require('../mongoose-encrypt');

const sample = { name: 'P', email: 'p@example.com', phone: '0911111111', address: 'Da Nang' };

// Mongoose queries are lazy: they must be awaited INSIDE run(), otherwise exec() runs outside the context.
const asUser = (isShowDecrypted, fn) => userContextStore.run({ isShowDecrypted }, async () => await fn());

describe('permission-based decryption (validAccessData: true)', () => {
    let Model;
    let id;

    before(async () => {
        await db.connect();
        Model = buildModel({ validAccessData: true });
        id = (await asUser(true, () => Model.create(sample)))._id;
    });

    after(async () => {
        await db.disconnect();
    });

    it('decrypts when isShowDecrypted is true', async () => {
        const doc = await asUser(true, () => Model.findById(id));
        assert.equal(doc.email, sample.email);
        assert.equal(doc.phone, sample.phone);
    });

    it('keeps ciphertext when isShowDecrypted is false', async () => {
        const doc = await asUser(false, () => Model.findById(id));
        assert.notEqual(doc.email, sample.email);
        assert.match(doc.email, /^[0-9a-f]+$/);
    });

    it('keeps ciphertext when no context is set', async () => {
        const doc = await Model.findById(id);
        assert.notEqual(doc.email, sample.email);
    });

    it('create() result follows the context', async () => {
        const denied = await asUser(false, () => Model.create({ ...sample, email: 'c1@example.com' }));
        assert.notEqual(denied.email, 'c1@example.com');

        const allowed = await asUser(true, () => Model.create({ ...sample, email: 'c2@example.com' }));
        assert.equal(allowed.email, 'c2@example.com');
    });

    it('aggregate() follows the context and never leaks hashField/ivField', async () => {
        const denied = await asUser(false, () => Model.aggregate([{ $match: { _id: id } }]));
        assert.notEqual(denied[0].email, sample.email);
        assert.equal(denied[0].hashField, undefined);
        assert.equal(denied[0].ivField, undefined);

        const allowed = await asUser(true, () => Model.aggregate([{ $match: { _id: id } }]));
        assert.equal(allowed[0].email, sample.email);
    });

    it('insertMany() result follows the context', async () => {
        const denied = await asUser(false, () => Model.insertMany([{ ...sample, email: 'im1@example.com' }]));
        assert.notEqual(denied[0].email, 'im1@example.com');

        const allowed = await asUser(true, () => Model.insertMany([{ ...sample, email: 'im2@example.com' }]));
        assert.equal(allowed[0].email, 'im2@example.com');

        const reread = await asUser(true, () => Model.findById(denied[0]._id));
        assert.equal(reread.email, 'im1@example.com');
    });

    it('search by encrypted field still works without decryption rights', async () => {
        const found = await asUser(false, () => Model.find({ email: sample.email }));
        assert.equal(found.length, 1);
        assert.equal(String(found[0]._id), String(id));
    });
});

describe('default options keep v1 behaviour (always decrypt)', () => {
    let Model;

    before(async () => {
        await db.connect();
        Model = buildModel();
    });

    after(async () => {
        await db.disconnect();
    });

    it('decrypts even when isShowDecrypted is false', async () => {
        const created = await Model.create(sample);
        const doc = await asUser(false, () => Model.findById(created._id));
        assert.equal(doc.email, sample.email);
    });
});

describe('re-saving without decryption rights must not corrupt data', () => {
    let Model;

    before(async () => {
        await db.connect();
        Model = buildModel({ validAccessData: true });
    });

    after(async () => {
        await db.disconnect();
    });

    it('changing a plain field keeps encrypted fields intact', async () => {
        const { _id } = await asUser(true, () => Model.create({ ...sample, email: 'keep@example.com' }));
        const before = await Model.collection.findOne({ _id });

        await asUser(false, async () => {
            const doc = await Model.findById(_id);
            doc.name = 'Renamed without rights';
            await doc.save();
        });

        const raw = await Model.collection.findOne({ _id });
        assert.equal(raw.email, before.email, 'ciphertext must be unchanged');
        assert.deepEqual(raw.hashField, before.hashField);
        assert.deepEqual(raw.ivField, before.ivField);

        const doc = await asUser(true, () => Model.findById(_id));
        assert.equal(doc.name, 'Renamed without rights');
        assert.equal(doc.email, 'keep@example.com');
    });

    it('setting a new value on an encrypted field encrypts only that field', async () => {
        const { _id } = await asUser(true, () => Model.create({ ...sample, email: 'old@example.com' }));
        const before = await Model.collection.findOne({ _id });

        await asUser(false, async () => {
            const doc = await Model.findById(_id);
            doc.email = 'new@example.com';
            await doc.save();
        });

        const raw = await Model.collection.findOne({ _id });
        assert.notEqual(raw.email, 'new@example.com');
        assert.equal(raw.phone, before.phone, 'untouched field must keep its ciphertext');
        assert.equal(raw.hashField.phone, before.hashField.phone);

        const doc = await asUser(true, () => Model.findById(_id));
        assert.equal(doc.email, 'new@example.com');
        assert.equal(doc.phone, sample.phone);
        assert.equal((await Model.find({ email: 'old@example.com' })).length, 0);
        assert.equal((await Model.find({ email: 'new@example.com' })).length, 1);
    });

    it('clearing an encrypted field removes its stale hash', async () => {
        const { _id } = await asUser(true, () => Model.create({ ...sample, email: 'gone@example.com' }));

        await asUser(true, async () => {
            const doc = await Model.findById(_id);
            doc.email = '';
            await doc.save();
        });

        assert.equal((await Model.find({ email: 'gone@example.com' })).length, 0);
    });
});
