const mongoose = require('mongoose');
const { MongooseEncryptPlugin } = require('../../mongoose-encrypt');

// Fixed test keys (32 bytes each). Never use these in production.
const ENCRYPTION_KEY = Buffer.alloc(32, 1).toString('base64');
const HASH_KEY = Buffer.alloc(32, 2).toString('hex');
// Key of plugin v1, used by tests of the `legacy` option.
const SALT = 'vZYt@CAkuMKB9Z#SHZF4d7puRt!MhCiK';
const FIELDS = ['email', 'phone', 'address'];

let counter = 0;

/**
 * Build a fresh model with the plugin applied.
 * @param {Object} pluginOptions - extra plugin options (merged over fields + test keys)
 * @param {Object} [opts]
 * @param {Object} [opts.schemaOptions] - extra mongoose schema options
 * @param {Function} [opts.extend] - called with the schema before the plugin is applied
 */
function buildModel(pluginOptions = {}, { schemaOptions = {}, extend } = {}) {
    const schema = new mongoose.Schema({
        name: { type: String, required: true },
        email: { type: String },
        phone: { type: String, default: '' },
        address: { type: String, default: '' },
    }, { timestamps: true, ...schemaOptions });

    if (extend) {
        extend(schema);
    }

    schema.plugin(MongooseEncryptPlugin, { fields: FIELDS, encryptionKey: ENCRYPTION_KEY, hashKey: HASH_KEY, ...pluginOptions });

    counter += 1;
    return mongoose.model(`EncryptTest${counter}`, schema);
}

const sample = { name: 'A', email: 'a@example.com', phone: '0977777777', address: 'Ho Chi Minh City' };

module.exports = { buildModel, sample, SALT, FIELDS, ENCRYPTION_KEY, HASH_KEY };
