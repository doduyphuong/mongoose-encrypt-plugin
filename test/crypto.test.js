const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const mongoose = require('mongoose');
const db = require('./helpers/db');
const { buildModel, sample, SALT } = require('./helpers/models');
const { pending } = require('./helpers/pending');
const { MongooseEncryptPlugin } = require('../mongoose-encrypt');

/** Flip the last hex digit of the stored ciphertext of `field`. */
async function tamper(Model, _id, field) {
    const raw = await Model.collection.findOne({ _id });
    const value = raw[field];
    const last = value.at(-1) === '0' ? '1' : '0';
    await Model.collection.updateOne({ _id }, { $set: { [field]: value.slice(0, -1) + last } });
    return value.slice(0, -1) + last;
}

describe('#14 key validation happens when the plugin is applied', () => {
    it('#14 rejects a key that is not 32 bytes with a clear message', pending('GD 1'), () => {
        const schema = new mongoose.Schema({ email: String });
        assert.throws(
            () => schema.plugin(MongooseEncryptPlugin, { fields: ['email'], salt: `${SALT}x` }),
            /32 bytes/,
        );
    });

    it('#14 rejects a missing key with a clear message (not a TypeError)', pending('GD 1'), () => {
        const schema = new mongoose.Schema({ email: String });
        assert.throws(
            () => schema.plugin(MongooseEncryptPlugin, { fields: ['email'] }),
            (err) => !(err instanceof TypeError) && /key/i.test(err.message),
        );
    });
});

describe('#15 / #17 integrity and decrypt errors', () => {
    let Model;
    let KeepModel;

    before(async () => {
        await db.connect();
        Model = buildModel();
        KeepModel = buildModel({ onDecryptError: 'keep' });
    });

    after(async () => {
        await db.disconnect();
    });

    it('#15 a tampered ciphertext is detected instead of returning garbage', pending('GD 1'), async () => {
        const { _id } = await Model.create({ ...sample, email: 'tamper@example.com' });
        await tamper(Model, _id, 'email');
        await assert.rejects(Model.findById(_id));
    });

    it('#17 onDecryptError: "keep" returns the stored value and keeps the query alive', pending('GD 1'), async () => {
        const ok = await KeepModel.create({ ...sample, name: 'ok', email: 'ok@example.com' });
        const bad = await KeepModel.create({ ...sample, name: 'bad', email: 'bad@example.com' });
        const stored = await tamper(KeepModel, bad._id, 'email');

        const docs = await KeepModel.find({ _id: { $in: [ok._id, bad._id] } }).sort({ name: -1 });
        assert.equal(docs.length, 2);
        assert.equal(docs[0].email, 'ok@example.com');
        assert.equal(docs[1].email, stored);
    });
});
