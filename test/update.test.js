const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const db = require('./helpers/db');
const { buildModel, sample } = require('./helpers/models');

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

    it('#8 replaceOne encrypts the replacement document', async () => {
        const created = await Model.create({ ...sample, email: 'rep@example.com' });
        await Model.replaceOne({ _id: created._id }, { name: 'Replaced', email: 'replaced@example.com' });

        const raw = await Model.collection.findOne({ _id: created._id });
        assert.notEqual(raw.email, 'replaced@example.com');
        assert.equal((await Model.findById(created._id)).email, 'replaced@example.com');
    });

    it('findOneAndReplace encrypts the replacement and returns it decrypted', async () => {
        const created = await Model.create({ ...sample, email: 'far@example.com' });
        const replaced = await Model.findOneAndReplace(
            { email: 'far@example.com' },
            { name: 'Far', email: 'far2@example.com' },
            { returnDocument: 'after' },
        );
        assert.equal(replaced.email, 'far2@example.com');

        const raw = await Model.collection.findOne({ _id: created._id });
        assert.match(raw.email, /^v2:/);
        assert.equal((await Model.find({ email: 'far2@example.com' })).length, 1);
    });

    it('$setOnInsert encrypts the value of an upserted document', async () => {
        await Model.updateOne({ name: 'Upserted' }, { $setOnInsert: { email: 'ups@example.com' } }, { upsert: true });

        const raw = await Model.collection.findOne({ name: 'Upserted' });
        assert.match(raw.email, /^v2:/);
        assert.equal((await Model.findOne({ email: 'ups@example.com' })).name, 'Upserted');
    });

    it('$unset on an encrypted field also removes its hash', async () => {
        const created = await Model.create({ ...sample, email: 'unset@example.com' });
        await Model.updateOne({ _id: created._id }, { $unset: { email: 1 } });

        const raw = await Model.collection.findOne({ _id: created._id });
        assert.equal(raw.email, undefined);
        assert.equal(raw.hashField?.email, undefined);
    });

    it('other update operators on an encrypted field throw UnsupportedOperatorError', async () => {
        const isUnsupported = (err) => err.name === 'UnsupportedOperatorError';
        const created = await Model.create({ ...sample, email: 'ops@example.com' });

        await assert.rejects(Model.updateOne({ _id: created._id }, { $push: { email: 'x' } }), isUnsupported);
        await assert.rejects(Model.updateOne({ _id: created._id }, { $rename: { email: 'mail' } }), isUnsupported);
        await assert.rejects(Model.updateOne({ _id: created._id }, { $rename: { name: 'email' } }), isUnsupported);
        await assert.rejects(Model.updateOne({ _id: created._id }, { $set: { 'email.x': 'y' } }), isUnsupported);
    });

    it('Mongoose 9: an update pipeline touching an encrypted field is rejected before reaching the DB', async () => {
        const created = await Model.create({ ...sample, email: 'pipe@example.com' });
        await assert.rejects(
            Model.findOneAndUpdate({ _id: created._id }, [{ $set: { email: 'plain@example.com' } }], { updatePipeline: true }),
            (err) => err.name === 'UnsupportedOperatorError',
        );

        const raw = await Model.collection.findOne({ _id: created._id });
        assert.notEqual(raw.email, 'plain@example.com', 'plaintext must never reach the database');
    });
});
