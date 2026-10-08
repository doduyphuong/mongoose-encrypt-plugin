const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const db = require('./helpers/db');
const { buildModel, sample } = require('./helpers/models');

describe('bulkWrite / bulkSave', () => {
    let Model;

    before(async () => {
        await db.connect();
        Model = buildModel();
    });

    after(async () => {
        await db.disconnect();
    });

    it('bulkWrite encrypts insertOne, updateOne and replaceOne, and rewrites every filter', async () => {
        await Model.bulkWrite([
            { insertOne: { document: { ...sample, name: 'B1', email: 'b1@example.com' } } },
            { insertOne: { document: { ...sample, name: 'B2', email: 'b2@example.com' } } },
            { insertOne: { document: { ...sample, name: 'B3', email: 'b3@example.com' } } },
        ]);

        for (const raw of await Model.collection.find({ name: /^B/ }).toArray()) {
            assert.match(raw.email, /^v2:/, `${raw.name} must be encrypted`);
        }

        const result = await Model.bulkWrite([
            { updateOne: { filter: { email: 'b1@example.com' }, update: { $set: { phone: '0900' } } } },
            { replaceOne: { filter: { email: 'b2@example.com' }, replacement: { name: 'B2r', email: 'b2r@example.com' } } },
            { deleteOne: { filter: { email: 'b3@example.com' } } },
        ]);
        assert.equal(result.matchedCount, 2);
        assert.equal(result.deletedCount, 1);

        const b1 = await Model.collection.findOne({ name: 'B1' });
        assert.match(b1.phone, /^v2:/);
        assert.equal((await Model.findOne({ phone: '0900' })).name, 'B1');

        const b2 = await Model.collection.findOne({ name: 'B2r' });
        assert.match(b2.email, /^v2:/);
        assert.equal((await Model.findOne({ email: 'b2r@example.com' })).name, 'B2r');
    });

    it('bulkWrite rejects an operator that cannot work on an encrypted field', async () => {
        await assert.rejects(
            Model.bulkWrite([{ updateOne: { filter: { name: 'B1' }, update: { $push: { email: 'x' } } } }]),
            (err) => err.name === 'UnsupportedOperatorError',
        );
    });

    it('bulkSave encrypts new and modified documents', async () => {
        const created = await Model.create({ ...sample, name: 'S1', email: 's1@example.com' });
        const loaded = await Model.findById(created._id);
        loaded.email = 's1b@example.com';
        const fresh = new Model({ ...sample, name: 'S2', email: 's2@example.com' });

        await Model.bulkSave([loaded, fresh]);

        const s1 = await Model.collection.findOne({ _id: created._id });
        const s2 = await Model.collection.findOne({ _id: fresh._id });
        assert.match(s1.email, /^v2:/);
        assert.match(s2.email, /^v2:/);
        assert.equal((await Model.findOne({ email: 's1b@example.com' })).name, 'S1');
        assert.equal((await Model.findOne({ email: 's2@example.com' })).name, 'S2');
        assert.equal(await Model.countDocuments({ email: 's1@example.com' }), 0);
    });
});
