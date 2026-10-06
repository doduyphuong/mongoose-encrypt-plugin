const mongoose = require('mongoose');
const { MongooseEncryptPlugin } = require('../../mongoose-encrypt');

const SALT = 'vZYt@CAkuMKB9Z#SHZF4d7puRt!MhCiK';
const FIELDS = ['email', 'phone', 'address'];

let counter = 0;

/**
 * Build a fresh model with the plugin applied.
 * @param {Object} pluginOptions - extra plugin options (merged over fields + salt)
 */
function buildModel(pluginOptions = {}) {
    const schema = new mongoose.Schema({
        name: { type: String, required: true },
        email: { type: String },
        phone: { type: String, default: '' },
        address: { type: String, default: '' },
    }, { timestamps: true });

    schema.plugin(MongooseEncryptPlugin, { fields: FIELDS, salt: SALT, ...pluginOptions });

    counter += 1;
    return mongoose.model(`EncryptTest${counter}`, schema);
}

module.exports = { buildModel, SALT, FIELDS };
