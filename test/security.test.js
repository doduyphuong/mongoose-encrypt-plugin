const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const mongoose = require('mongoose');
const db = require('./helpers/db');
const { buildModel, SALT, FIELDS } = require('./helpers/models');
const { MongooseEncryptPlugin } = require('../mongoose-encrypt');
const {
    WARNING_CODE,
    getPatchedMongooseVersion,
    warnIfVulnerableMongoose
} = require('../helpers/security');

/**
 * Run `fn` and collect the plugin's security warnings emitted while it runs.
 */
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
    it('reports the patched release for vulnerable 7.x / 8.x versions', () => {
        assert.equal(getPatchedMongooseVersion('7.0.0'), '7.8.13');
        assert.equal(getPatchedMongooseVersion('7.8.12'), '7.8.13');
        assert.equal(getPatchedMongooseVersion('8.0.0'), '8.24.7');
        assert.equal(getPatchedMongooseVersion('8.24.5'), '8.24.7');
        assert.equal(getPatchedMongooseVersion('8.24.6'), '8.24.7');
    });

    it('treats patched and unsupported versions as not affected', () => {
        assert.equal(getPatchedMongooseVersion('7.8.13'), null);
        assert.equal(getPatchedMongooseVersion('8.24.7'), null);
        assert.equal(getPatchedMongooseVersion('8.24.9'), null);
        assert.equal(getPatchedMongooseVersion('8.25.0'), null);
        assert.equal(getPatchedMongooseVersion('9.0.0'), null);
        assert.equal(getPatchedMongooseVersion('6.13.0'), null);
        assert.equal(getPatchedMongooseVersion(undefined), null);
        assert.equal(getPatchedMongooseVersion('not-a-version'), null);
    });

    it('emits one SecurityWarning per vulnerable version', async () => {
        const warnings = await collectWarnings(() => {
            assert.equal(warnIfVulnerableMongoose('8.1.0-test'), true);
            assert.equal(warnIfVulnerableMongoose('8.1.0-test'), false);
            assert.equal(warnIfVulnerableMongoose('7.1.0-test'), true);
            assert.equal(warnIfVulnerableMongoose('8.24.9'), false);
        });

        assert.equal(warnings.length, 2);
        assert.equal(warnings[0].name, 'SecurityWarning');
        assert.match(warnings[0].message, /Mongoose 8\.1\.0-test .*Upgrade Mongoose to 8\.24\.7 or later/);
        assert.match(warnings[1].message, /Upgrade Mongoose to 7\.8\.13 or later/);
    });

    it('checks the Mongoose instance the schema belongs to when the plugin is applied', async () => {
        const warnings = await collectWarnings(() => {
            for (let i = 0; i < 2; i++) {
                const schema = new mongoose.Schema({ email: String });
                // Simulate an application running a vulnerable Mongoose release.
                const base = Object.create(mongoose, { version: { value: '8.2.0-test' } });
                Object.defineProperty(schema, 'base', { value: base, configurable: true });
                schema.plugin(MongooseEncryptPlugin, { fields: ['email'], salt: SALT });
            }
        });

        assert.equal(warnings.length, 1);
        assert.match(warnings[0].message, /Mongoose 8\.2\.0-test/);
    });

    it('does not warn for the Mongoose version used by this test run when it is patched', async (t) => {
        if (getPatchedMongooseVersion(mongoose.version)) {
            t.skip(`test run uses vulnerable Mongoose ${mongoose.version}`);
            return;
        }

        const warnings = await collectWarnings(() => {
            const schema = new mongoose.Schema({ email: String });
            schema.plugin(MongooseEncryptPlugin, { fields: FIELDS, salt: SALT });
        });

        assert.equal(warnings.length, 0);
    });
});

describe('sanitizeFilter and mongoose.trusted()', () => {
    let Model;
    let MixedModel;

    before(async () => {
        await db.connect();
        Model = buildModel();
        MixedModel = buildModel({ haveDataNotEncrypt: true });

        for (const M of [Model, MixedModel]) {
            await M.create({ name: 'A', email: 'a@example.com' });
            await M.create({ name: 'B', email: 'b@example.com' });
        }
    });

    after(async () => {
        await db.disconnect();
    });

    it('blocks an injected operator on an encrypted field', async () => {
        const filter = { email: { $ne: 'nobody@example.com' } };

        assert.equal((await Model.find(filter).setOptions({ sanitizeFilter: true })).length, 0);
        assert.equal(await Model.countDocuments(filter).setOptions({ sanitizeFilter: true }), 0);
    });

    it('keeps a plain equality filter working', async () => {
        const docs = await Model.find({ email: 'a@example.com' }).setOptions({ sanitizeFilter: true });

        assert.deepEqual(docs.map((d) => d.name), ['A']);
    });

    it('honours mongoose.trusted() on an encrypted field', async () => {
        const docs = await Model.find({ email: mongoose.trusted({ $ne: 'a@example.com' }) })
            .setOptions({ sanitizeFilter: true });

        assert.deepEqual(docs.map((d) => d.name), ['B']);
        assert.equal(
            await Model.countDocuments({ email: mongoose.trusted({ $ne: 'a@example.com' }) })
                .setOptions({ sanitizeFilter: true }),
            1
        );
    });

    it('honours mongoose.trusted() with haveDataNotEncrypt', async () => {
        const docs = await MixedModel.find({ email: mongoose.trusted({ $ne: 'a@example.com' }) })
            .setOptions({ sanitizeFilter: true });

        assert.deepEqual(docs.map((d) => d.name), ['B']);
    });
});
