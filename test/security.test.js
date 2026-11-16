const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const mongoose = require('mongoose');
const db = require('./helpers/db');
const { buildModel, SALT, FIELDS, ENCRYPTION_KEY, HASH_KEY } = require('./helpers/models');
const { MongooseEncryptPlugin } = require('../mongoose-encrypt');
const { WARNING_CODE, getPatchedMongooseVersion, warnIfVulnerableMongoose } = require('../src/security');

const names = (docs) => docs.map(d => d.name).sort();
const sanitized = { sanitizeFilter: true };

/** Run `fn` and collect the plugin's security warnings emitted while it runs. */
async function collectWarnings(fn) {
    const warnings = [];
    const listener = (warning) => {
        if (warning.code === WARNING_CODE) warnings.push(warning);
    };

    process.on('warning', listener);
    try {
        fn();
    } finally {
        // process.emitWarning dispatches the 'warning' event on the next tick.
        await new Promise((resolve) => setImmediate(resolve));
        process.off('warning', listener);
    }

    return warnings;
}

describe('Mongoose version check', () => {
    it('reports the patched release for vulnerable 9.x versions', () => {
        assert.equal(getPatchedMongooseVersion('9.0.0'), '9.11.4');
        assert.equal(getPatchedMongooseVersion('9.11.0'), '9.11.4');
        assert.equal(getPatchedMongooseVersion('9.11.3'), '9.11.4');
    });

    it('treats patched and unsupported versions as not affected', () => {
        assert.equal(getPatchedMongooseVersion('9.11.4'), null);
        assert.equal(getPatchedMongooseVersion('9.12.1'), null);
        assert.equal(getPatchedMongooseVersion('10.0.0'), null);
        assert.equal(getPatchedMongooseVersion('8.24.5'), null);
        assert.equal(getPatchedMongooseVersion(undefined), null);
        assert.equal(getPatchedMongooseVersion('not-a-version'), null);
    });

    it('emits one SecurityWarning per vulnerable version', async () => {
        const warnings = await collectWarnings(() => {
            assert.equal(warnIfVulnerableMongoose('9.1.0-test'), true);
            assert.equal(warnIfVulnerableMongoose('9.1.0-test'), false);
            assert.equal(warnIfVulnerableMongoose('9.12.1'), false);
        });

        assert.equal(warnings.length, 1);
        assert.equal(warnings[0].name, 'SecurityWarning');
        assert.match(warnings[0].message, /Mongoose 9\.1\.0-test .*Upgrade Mongoose to 9\.11\.4 or later/);
    });

    it('checks the Mongoose instance the schema belongs to when the plugin is applied', async () => {
        const warnings = await collectWarnings(() => {
            for (let i = 0; i < 2; i++) {
                const schema = new mongoose.Schema({ email: String });
                // Simulate an application running a vulnerable Mongoose release.
                const base = Object.create(mongoose, { version: { value: '9.2.0-test' } });
                Object.defineProperty(schema, 'base', { value: base, configurable: true });
                schema.plugin(MongooseEncryptPlugin, { fields: ['email'], encryptionKey: ENCRYPTION_KEY, hashKey: HASH_KEY });
            }
        });

        assert.equal(warnings.length, 1);
        assert.match(warnings[0].message, /Mongoose 9\.2\.0-test/);
    });

    it('does not warn for the Mongoose version used by this test run when it is patched', async (t) => {
        if (getPatchedMongooseVersion(mongoose.version)) {
            t.skip(`test run uses vulnerable Mongoose ${mongoose.version}`);
            return;
        }

        const warnings = await collectWarnings(() => {
            const schema = new mongoose.Schema({ email: String, phone: String, address: String });
            schema.plugin(MongooseEncryptPlugin, { fields: FIELDS, encryptionKey: ENCRYPTION_KEY, hashKey: HASH_KEY });
        });

        assert.equal(warnings.length, 0);
    });
});

describe('sanitizeFilter and mongoose.trusted()', () => {
    const variants = {
        default: {},
        legacy: { legacy: { salt: SALT } },
        haveDataNotEncrypt: { haveDataNotEncrypt: true },
    };
    const models = {};

    before(async () => {
        await db.connect();

        for (const [key, options] of Object.entries(variants)) {
            models[key] = buildModel(options);
            await models[key].create([{ name: 'A', email: 'a@example.com' }, { name: 'B', email: 'b@example.com' }]);
        }
    });

    after(async () => {
        await db.disconnect();
    });

    for (const key of Object.keys(variants)) {
        describe(key, () => {
            it('keeps plain equality and a lone $eq working', async () => {
                const Model = models[key];

                assert.deepEqual(names(await Model.find({ email: 'a@example.com' }).setOptions(sanitized)), ['A']);
                assert.deepEqual(names(await Model.find({ email: { $eq: 'b@example.com' } }).setOptions(sanitized)), ['B']);
                assert.equal(await Model.countDocuments({ email: 'a@example.com' }).setOptions(sanitized), 1);
                assert.deepEqual(
                    names(await Model.find({ $or: [{ email: 'a@example.com' }, { name: 'B' }] }).setOptions(sanitized)),
                    ['A', 'B']
                );
            });

            it('neutralises operators sent by a user', async () => {
                const Model = models[key];
                // sanitizeFilter turns them into an equality on the operator object: no match, or a CastError
                // on the plaintext path (same as without the plugin).
                const matches = async (query) => {
                    try {
                        return (await query.setOptions(sanitized)).length;
                    } catch (err) {
                        assert.equal(err.name, 'CastError');
                        return 0;
                    }
                };

                assert.equal(await matches(Model.find({ email: { $ne: 'nobody@example.com' } })), 0);
                assert.equal(await matches(Model.find({ email: { $in: ['a@example.com', 'b@example.com'] } })), 0);
                assert.equal(await matches(Model.find({ email: { $exists: true } })), 0);
            });

            it('honours mongoose.trusted()', async () => {
                const Model = models[key];

                assert.deepEqual(
                    names(await Model.find({ email: mongoose.trusted({ $ne: 'a@example.com' }) }).setOptions(sanitized)),
                    ['B']
                );
                assert.deepEqual(
                    names(await Model.find({ email: mongoose.trusted({ $in: ['a@example.com', 'b@example.com'] }) }).setOptions(sanitized)),
                    ['A', 'B']
                );
                assert.equal(
                    await Model.countDocuments({ email: mongoose.trusted({ $nin: ['a@example.com'] }) }).setOptions(sanitized),
                    1
                );
            });
        });
    }
});
