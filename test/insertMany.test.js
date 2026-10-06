const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const db = require('./helpers/db');
const { buildModel, sample } = require('./helpers/models');

describe('insertMany', () => {
    let Model;

    before(async () => {
        await db.connect();
        Model = buildModel();
    });

    after(async () => {
        await db.disconnect();
    });

    it('encrypts every document and returns decrypted values', async () => {
        const docs = await Model.insertMany([
            { ...sample, name: 'Many 1', email: 'many1@example.com' },
            { ...sample, name: 'Many 2', email: 'many2@example.com', phone: '' },
        ]);

        assert.equal(docs.length, 2);
        assert.equal(docs[0].email, 'many1@example.com');
        assert.equal(docs[1].phone, '');

        const raws = await Model.collection.find({ _id: { $in: docs.map(d => d._id) } }).sort({ name: 1 }).toArray();
        assert.notEqual(raws[0].email, 'many1@example.com');
        assert.notEqual(raws[0].hashField.email, raws[1].hashField.email, 'each document has its own hash');
        assert.equal(raws[1].hashField.phone, undefined, 'empty value is not hashed');
        assert.equal((await Model.find({ email: 'many2@example.com' })).length, 1);
    });

    it('accepts a single object and an empty array', async () => {
        const single = await Model.insertMany({ ...sample, name: 'Single', email: 'single@example.com' });
        assert.equal(single[0].email, 'single@example.com');
        assert.deepEqual(await Model.insertMany([]), []);
    });

    it('reports the original validation error', async () => {
        await assert.rejects(
            Model.insertMany([{ email: 'noname@example.com' }]),
            (err) => err.name === 'ValidationError' && /name/.test(err.message),
        );
    });

    it('works with lean: true', async () => {
        const docs = await Model.insertMany([{ ...sample, name: 'Lean', email: 'lean@example.com' }], { lean: true });
        assert.equal(docs[0].email, 'lean@example.com');

        const raw = await Model.collection.findOne({ name: 'Lean' });
        assert.notEqual(raw.email, 'lean@example.com');
        assert.equal((await Model.find({ email: 'lean@example.com' })).length, 1);
    });
});
