const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const mongoose = require('mongoose');
const db = require('./helpers/db');
const { buildModel, sample, SALT, ENCRYPTION_KEY, HASH_KEY } = require('./helpers/models');
const { MongooseEncryptPlugin, OptionsError, DecryptionError } = require('../mongoose-encrypt');

const apply = (options, definition = { email: String }) => {
    const schema = new mongoose.Schema(definition);
    schema.plugin(MongooseEncryptPlugin, { fields: ['email'], ...options });
    return schema;
};

/** Flip the last hex digit of the stored ciphertext of `field`. */
async function tamper(Model, _id, field) {
    const raw = await Model.collection.findOne({ _id });
    const value = raw[field];
    const last = value.at(-1) === '0' ? '1' : '0';
    await Model.collection.updateOne({ _id }, { $set: { [field]: value.slice(0, -1) + last } });
    return value.slice(0, -1) + last;
}

describe('#14 options are validated when the plugin is applied', () => {
    it('#14 rejects a key that is not 32 bytes with a clear message', () => {
        assert.throws(() => apply({ encryptionKey: `${SALT}x`, hashKey: HASH_KEY }), /encryptionKey.*32 bytes/);
        assert.throws(() => apply({ encryptionKey: ENCRYPTION_KEY, hashKey: 'short' }), /hashKey.*32 bytes/);
    });

    it('#14 rejects a missing key with a clear message (not a TypeError)', () => {
        assert.throws(() => apply({}), (err) => err instanceof OptionsError && /encryptionKey/.test(err.message));
        assert.throws(() => apply({ encryptionKey: ENCRYPTION_KEY }), (err) => err instanceof OptionsError && /hashKey/.test(err.message));
    });

    it('accepts Buffer, hex, base64 and 32-character keys', () => {
        assert.doesNotThrow(() => apply({ encryptionKey: crypto.randomBytes(32), hashKey: crypto.randomBytes(32).toString('hex') }));
        assert.doesNotThrow(() => apply({ encryptionKey: crypto.randomBytes(32).toString('base64'), hashKey: SALT }));
    });

    it('rejects the same key for encryption and hashing', () => {
        assert.throws(() => apply({ encryptionKey: ENCRYPTION_KEY, hashKey: ENCRYPTION_KEY }), OptionsError);
    });

    it('explains the v1 options that were removed', () => {
        assert.throws(() => apply({ salt: SALT }), /encryptionKey.*hashKey.*legacy/);
        assert.throws(() => apply({ encryptionKey: ENCRYPTION_KEY, hashKey: HASH_KEY, algorithm: 'aes-256-cbc' }), /AES-256-GCM/);
    });

    it('rejects unique: true on an encrypted field', () => {
        assert.throws(
            () => apply({ encryptionKey: ENCRYPTION_KEY, hashKey: HASH_KEY }, { email: { type: String, unique: true } }),
            /unique: \['email'\]/,
        );
    });

    it('rejects an encrypted field that is not a top-level String path', () => {
        const keys = { encryptionKey: ENCRYPTION_KEY, hashKey: HASH_KEY };
        assert.throws(() => apply(keys, { email: Number }), /only String fields/);
        assert.throws(() => apply(keys, { mail: String }), /not a top-level path/);
    });

    it('rejects invalid unique / onDecryptError / legacy options', () => {
        const keys = { encryptionKey: ENCRYPTION_KEY, hashKey: HASH_KEY };
        assert.throws(() => apply({ ...keys, unique: ['phone'] }), OptionsError);
        assert.throws(() => apply({ ...keys, onDecryptError: 'ignore' }), OptionsError);
        assert.throws(() => apply({ ...keys, legacy: { salt: SALT, algorithm: 'aes-128-cbc' } }), OptionsError);
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

    it('#15 a tampered ciphertext is detected instead of returning garbage', async () => {
        const { _id } = await Model.create({ ...sample, email: 'tamper@example.com' });
        await tamper(Model, _id, 'email');
        await assert.rejects(Model.findById(_id), (err) => err instanceof DecryptionError && err.field === 'email');
    });

    it('#17 onDecryptError: "keep" returns the stored value and keeps the query alive', async () => {
        const ok = await KeepModel.create({ ...sample, name: 'ok', email: 'ok@example.com' });
        const bad = await KeepModel.create({ ...sample, name: 'bad', email: 'bad@example.com' });
        const stored = await tamper(KeepModel, bad._id, 'email');

        const docs = await KeepModel.find({ _id: { $in: [ok._id, bad._id] } }).sort({ name: -1 });
        assert.equal(docs.length, 2);
        assert.equal(docs[0].email, 'ok@example.com');
        assert.equal(docs[1].email, stored);
    });
});

describe('legacy: data written by plugin v1', () => {
    let Model;

    /** Encrypt like plugin v1 (AES-256-CTR, hex, iv in ivField). */
    const v1Encrypt = (text) => {
        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv('aes-256-ctr', SALT, iv);
        return { iv: iv.toString('hex'), value: Buffer.concat([cipher.update(text), cipher.final()]).toString('hex') };
    };

    before(async () => {
        await db.connect();
        Model = buildModel({ legacy: { salt: SALT } });
    });

    after(async () => {
        await db.disconnect();
    });

    it('reads a v1 document and re-encrypts it with v2 on save', async () => {
        const email = v1Encrypt('old@example.com');
        const { insertedId } = await Model.collection.insertOne({
            name: 'V1',
            email: email.value,
            phone: '',
            address: '',
            hashField: { email: crypto.createHash('sha256').update('old@example.com').digest('base64') },
            ivField: { email: email.iv },
        });

        const doc = await Model.findById(insertedId);
        assert.equal(doc.email, 'old@example.com');

        await doc.save();
        const raw = await Model.collection.findOne({ _id: insertedId });
        assert.match(raw.email, /^v2:/);
        assert.equal(raw.ivField, undefined, 'ivField is removed once no v1 value is left');
        assert.equal((await Model.find({ email: 'old@example.com' })).length, 1);
    });
});
