const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const db = require('./helpers/db');
const { buildModel, sample } = require('./helpers/models');
const { pending } = require('./helpers/pending');

describe('updates', () => {
    let Model;

    before(async () => {
        await db.connect();
        Model = buildModel();
    });

    after(async () => {
        await db.disconnect();
    });

    it('findOneAndUpdate + $set encrypts the new value', async () => {
        const created = await Model.create({ ...sample, email: 'upd@example.com' });
        const updated = await Model.findOneAndUpdate({ _id: created._id }, { $set: { phone: '0900000000' } }, { returnDocument: 'after' });
        assert.equal(updated.phone, '0900000000');

        const raw = await Model.collection.findOne({ _id: created._id });
        assert.notEqual(raw.phone, '0900000000');
        assert.equal((await Model.find({ phone: '0900000000' })).length, 1);
    });

    it('updateOne with a top-level value encrypts it', async () => {
        const created = await Model.create({ ...sample, email: 'top@example.com' });
        await Model.updateOne({ _id: created._id }, { address: 'Hue' });

        const raw = await Model.collection.findOne({ _id: created._id });
        assert.notEqual(raw.address, 'Hue');
        assert.equal((await Model.findById(created._id)).address, 'Hue');
    });

    it('#5 clearing a field with updateOne removes its stale hash', async () => {
        const created = await Model.create({ ...sample, email: 'stale@example.com' });
        await Model.updateOne({ _id: created._id }, { $set: { email: '' } });
        assert.equal((await Model.find({ email: 'stale@example.com' })).length, 0);
    });

    it('#8 updateOne / updateMany match a filter on an encrypted field', async () => {
        await Model.create({ ...sample, name: 'F1', email: 'filter@example.com' });
        assert.equal((await Model.updateOne({ email: 'filter@example.com' }, { name: 'F1b' })).matchedCount, 1);
        assert.equal((await Model.updateMany({ email: 'filter@example.com' }, { name: 'F1c' })).matchedCount, 1);
    });

    it('#8 deleteOne / deleteMany / findOneAndDelete match a filter on an encrypted field', async () => {
        await Model.create([
            { ...sample, name: 'D1', email: 'd1@example.com' },
            { ...sample, name: 'D2', email: 'd2@example.com' },
            { ...sample, name: 'D3', email: 'd3@example.com' },
        ]);
        assert.equal((await Model.deleteOne({ email: 'd1@example.com' })).deletedCount, 1);
        assert.equal((await Model.deleteMany({ email: 'd2@example.com' })).deletedCount, 1);
        assert.equal((await Model.findOneAndDelete({ email: 'd3@example.com' }))?.name, 'D3');
    });

    it('#8 replaceOne encrypts the replacement document', pending('GD 3'), async () => {
        const created = await Model.create({ ...sample, email: 'rep@example.com' });
        await Model.replaceOne({ _id: created._id }, { name: 'Replaced', email: 'replaced@example.com' });

        const raw = await Model.collection.findOne({ _id: created._id });
        assert.notEqual(raw.email, 'replaced@example.com');
        assert.equal((await Model.findById(created._id)).email, 'replaced@example.com');
    });

    it('Mongoose 9: an update pipeline touching an encrypted field is rejected before reaching the DB', pending('GD 3'), async () => {
        const created = await Model.create({ ...sample, email: 'pipe@example.com' });
        await assert.rejects(
            Model.findOneAndUpdate({ _id: created._id }, [{ $set: { email: 'plain@example.com' } }], { updatePipeline: true }),
            (err) => err.name === 'UnsupportedOperatorError',
        );

        const raw = await Model.collection.findOne({ _id: created._id });
        assert.notEqual(raw.email, 'plain@example.com', 'plaintext must never reach the database');
    });
});
