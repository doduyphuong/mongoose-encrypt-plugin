const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const db = require('./helpers/db');
const { buildModel, sample } = require('./helpers/models');

const isUnsupported = (err) => err.name === 'UnsupportedOperatorError';
const names = (docs) => docs.map(d => d.name).sort();

describe('queries on encrypted fields', () => {
    let Model;

    before(async () => {
        await db.connect();
        Model = buildModel();
        await Model.create([
            { ...sample, name: 'Q1', email: 'q1@example.com', phone: '111' },
            { ...sample, name: 'Q2', email: 'q2@example.com', phone: '222' },
            { ...sample, name: 'Q3', email: 'q3@example.com', phone: '' },
        ]);
    });

    after(async () => {
        await db.disconnect();
    });

    it('decrypts on find() and findById()', async () => {
        const [doc] = await Model.find({ name: 'Q1' });
        assert.equal(doc.email, 'q1@example.com');
        assert.equal((await Model.findById(doc._id)).email, 'q1@example.com');
    });

    it('finds by equality, $eq and $ne', async () => {
        assert.deepEqual(names(await Model.find({ email: 'q1@example.com' })), ['Q1']);
        assert.deepEqual(names(await Model.find({ email: { $eq: 'q2@example.com' } })), ['Q2']);
        assert.deepEqual(names(await Model.find({ email: { $ne: 'q1@example.com' } })), ['Q2', 'Q3']);
    });

    it('finds by an encrypted field inside $or', async () => {
        assert.deepEqual(names(await Model.find({ $or: [{ email: 'q1@example.com' }, { name: 'Q3' }] })), ['Q1', 'Q3']);
    });

    it('countDocuments() and findOne() use the hash', async () => {
        assert.equal(await Model.countDocuments({ email: 'q2@example.com' }), 1);
        assert.equal((await Model.findOne({ email: 'q2@example.com' })).name, 'Q2');
    });

    it('#6 $in and $nin', async () => {
        assert.deepEqual(names(await Model.find({ email: { $in: ['q1@example.com', 'q3@example.com'] } })), ['Q1', 'Q3']);
        assert.deepEqual(names(await Model.find({ email: { $nin: ['q1@example.com'] } })), ['Q2', 'Q3']);
    });

    it('#6 $exists matches documents that store a non-empty value', async () => {
        assert.deepEqual(names(await Model.find({ phone: { $exists: true }, name: /^Q/ })), ['Q1', 'Q2']);
    });

    it('#6 non-string values are matched by their string form', async () => {
        assert.deepEqual(names(await Model.find({ phone: 111 })), ['Q1']);
    });

    it('#6 $regex, RegExp and range operators throw UnsupportedOperatorError', async () => {
        await assert.rejects(Model.find({ email: { $regex: 'q1' } }), isUnsupported);
        await assert.rejects(Model.find({ email: /q1/ }), isUnsupported);
        await assert.rejects(Model.find({ phone: { $gt: '100' } }), isUnsupported);
    });

    it('#7 $and with two encrypted fields keeps AND semantics', async () => {
        const docs = await Model.find({ $and: [{ email: 'q1@example.com' }, { phone: '222' }] });
        assert.equal(docs.length, 0);
    });

    it('#9 $regex inside $or throws instead of silently matching nothing', async () => {
        await assert.rejects(Model.find({ $or: [{ email: { $regex: 'q1@example.com' } }] }), isUnsupported);
    });

    it('#10 every key of an $or branch is rewritten, also when nested', async () => {
        assert.deepEqual(names(await Model.find({ $or: [{ name: 'Q1', email: 'q1@example.com' }] })), ['Q1']);
        assert.deepEqual(
            names(await Model.find({ $and: [{ $or: [{ email: 'q1@example.com' }, { email: 'q2@example.com' }] }, { name: { $ne: 'Q2' } }] })),
            ['Q1'],
        );
    });

    it('$nor on an encrypted field', async () => {
        assert.deepEqual(names(await Model.find({ $nor: [{ email: 'q1@example.com' }, { email: 'q2@example.com' }] })), ['Q3']);
    });

    it('an inclusion projection still returns decrypted values', async () => {
        const [doc] = await Model.find({ name: 'Q2' }, { name: 1, email: 1 });
        assert.equal(doc.email, 'q2@example.com');
        assert.equal(doc.phone, undefined);
    });

    it('does not modify the filter object passed by the caller', async () => {
        const filter = { email: 'q1@example.com', $or: [{ phone: '111' }] };
        const copy = JSON.parse(JSON.stringify(filter));
        await Model.find(filter);
        assert.deepEqual(filter, copy);
    });

    it('#11 an exclusion projection works', async () => {
        const [doc] = await Model.find({ name: 'Q1' }, { address: 0 });
        assert.equal(doc.email, 'q1@example.com');
        assert.equal(doc.address, undefined);
    });
});

describe('#7 haveDataNotEncrypt keeps the user $or intact', () => {
    let Model;

    before(async () => {
        await db.connect();
        Model = buildModel({ haveDataNotEncrypt: true });
        await Model.create({ ...sample, name: 'H1', email: 'h1@example.com' });
        await Model.collection.insertOne({ name: 'H2', email: 'h2@example.com', phone: '', address: '' });
    });

    after(async () => {
        await db.disconnect();
    });

    it('matches encrypted and plaintext documents by equality', async () => {
        assert.deepEqual(names(await Model.find({ email: 'h1@example.com' })), ['H1']);
        assert.deepEqual(names(await Model.find({ email: 'h2@example.com' })), ['H2']);
    });

    it('$in matches both encrypted and plaintext documents', async () => {
        assert.deepEqual(names(await Model.find({ email: { $in: ['h1@example.com', 'h2@example.com'] } })), ['H1', 'H2']);
    });

    it('$ne excludes the value whether it is encrypted or not', async () => {
        assert.deepEqual(names(await Model.find({ email: { $ne: 'h1@example.com' } })), ['H2']);
        assert.deepEqual(names(await Model.find({ email: { $ne: 'h2@example.com' } })), ['H1']);
    });

    it('#7 a top-level encrypted condition is ANDed with the user $or', async () => {
        const docs = await Model.find({ email: 'h1@example.com', $or: [{ name: 'H2' }, { name: 'nobody' }] });
        assert.equal(docs.length, 0);
    });
});
