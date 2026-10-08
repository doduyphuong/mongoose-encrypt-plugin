const mongoose = require('mongoose');
const { normalizeOptions } = require('./options');
const { createCodec } = require('./codec');
const { createFilterRewriter } = require('./query');
const { OptionsError } = require('./errors');
const { registerWriteHooks } = require('./hooks/write');
const { registerReadHooks } = require('./hooks/read');
const { registerMigration } = require('./migrate');

/**
 * Encrypt fields of a schema with AES-256-GCM and keep them searchable by equality through a keyed hash.
 *
 * ### Example:
 *
 *      const { MongooseEncryptPlugin } = require('mongoose-encrypt-plugin');
 *
 *      UserSchema.plugin(MongooseEncryptPlugin, {
 *          fields: ['email', 'phone'],
 *          encryptionKey: process.env.ENCRYPTION_KEY, // 32 bytes: base64, hex or Buffer
 *          hashKey: process.env.HASH_KEY,             // 32 bytes, different from encryptionKey
 *          unique: ['email'],
 *      });
 *
 * ### Options:
 *
 * - [fields] string[] - required. Fields to encrypt (top-level String paths)
 * - [encryptionKey] Buffer|string - required. 32-byte AES-256-GCM key
 * - [hashKey] Buffer|string - required. 32-byte HMAC key for the search hash
 * - [unique] string[] - defaults to []. Encrypted fields that must be unique (index on the hash)
 * - [onDecryptError] 'throw'|'keep' - defaults to 'throw'. 'keep' returns the stored value instead
 * - [legacy] { salt, algorithm } - optional. Key and algorithm of plugin v1 to read data written by v1
 * - [hashField] string - defaults to `hashField`
 * - [ivField] string - defaults to `ivField` (only used by data written by v1)
 * - [hideIV] bool - defaults to true
 * - [haveDataNotEncrypt] bool - defaults to false. If true, queries also match plaintext values
 * - [validAccessData] bool - defaults to false. If true, values are decrypted only inside `runWithDecryption(true, fn)`
 *
 * @param {import('mongoose').Schema} schema - The mongoose schema
 * @param {Object} rawOptions - The plugin options
 */
function MongooseEncryptPlugin(schema, rawOptions) {
    const options = normalizeOptions(rawOptions);

    options.fields.forEach(field => {
        const path = schema.path(field);

        if (!path) {
            throw new OptionsError(`Field "${field}" is not a top-level path of the schema. Define it before applying the plugin`);
        }

        if (path.instance !== 'String') {
            throw new OptionsError(`Field "${field}" is a ${path.instance}: only String fields can be encrypted`);
        }

        if (path.options?.unique) {
            throw new OptionsError(`Field "${field}" is encrypted, so "unique: true" on it has no effect. Use the plugin option "unique: ['${field}']" instead`);
        }
    });

    schema.add({ [options.hashField]: mongoose.Schema.Types.Mixed, [options.ivField]: mongoose.Schema.Types.Mixed });

    options.unique.forEach(field => {
        schema.index({ [`${options.hashField}.${field}`]: 1 }, { unique: true, sparse: true });
    });

    const codec = createCodec(options);
    const rewriteFilter = createFilterRewriter({
        fields: options.fields,
        hashField: options.hashField,
        haveDataNotEncrypt: options.haveDataNotEncrypt,
        hashValues: codec.hashValues,
    });
    const ctx = { options, codec, rewriteFilter };

    registerWriteHooks(schema, ctx);
    registerReadHooks(schema, ctx);
    registerMigration(schema, ctx);
}

module.exports = { MongooseEncryptPlugin };
