const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const db = require('./helpers/db');
const { buildModel, sample } = require('./helpers/models');
const { pending } = require('./helpers/pending');

describe('toJSON', () => {
    let Model;

    before(async () => {
        await db.connect();
        Model = buildModel({}, {
            schemaOptions: {
                toJSON: {
                    virtuals: true,
                    transform: (doc, ret) => { ret.transformed = true; return ret; },
                },
            },
            extend: (schema) => schema.virtual('label').get(function () { return `label:${this.name}`; }),
        });
    });

    after(async () => {
        await db.disconnect();
    });

    it('hides hashField and ivField', async () => {
        const created = await Model.create({ ...sample, email: 'json@example.com' });
        const json = (await Model.findById(created._id)).toJSON();
        assert.equal(json.hashField, undefined);
        assert.equal(json.ivField, undefined);
        assert.equal(json.email, 'json@example.com');
    });

    it('#16 keeps the schema toJSON options (virtuals, transform)', pending('GD 3'), async () => {
        const created = await Model.create({ ...sample, name: 'V', email: 'virt@example.com' });
        const json = (await Model.findById(created._id)).toJSON();
        assert.equal(json.label, 'label:V');
        assert.equal(json.transformed, true);
    });
});
