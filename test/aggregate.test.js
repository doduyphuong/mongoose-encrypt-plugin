const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const db = require('./helpers/db');
const { buildModel, sample } = require('./helpers/models');

describe('aggregate', () => {
    let Model;

    before(async () => {
        await db.connect();
        Model = buildModel();
        await Model.create([
            { ...sample, name: 'Agg1', email: 'agg1@example.com' },
            { ...sample, name: 'Agg2', email: 'agg2@example.com' },
        ]);
    });

    after(async () => {
        await db.disconnect();
    });

    it('decrypts results and hides hashField / ivField', async () => {
        const rows = await Model.aggregate([{ $match: { name: 'Agg1' } }]);
        assert.equal(rows.length, 1);
        assert.equal(rows[0].email, 'agg1@example.com');
        assert.equal(rows[0].hashField, undefined);
        assert.equal(rows[0].ivField, undefined);
    });

    it('decrypts the encrypted fields kept by a $project', async () => {
        const rows = await Model.aggregate([{ $match: { name: 'Agg1' } }, { $project: { email: 1 } }]);
        assert.equal(rows[0].email, 'agg1@example.com');
    });

    it('#13 the first $match on an encrypted field is rewritten', async () => {
        const rows = await Model.aggregate([{ $match: { email: 'agg2@example.com' } }]);
        assert.equal(rows.length, 1);
        assert.equal(rows[0].name, 'Agg2');
    });
});
