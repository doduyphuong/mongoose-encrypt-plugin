const mongoose = require('mongoose');
const { normalizeOptions } = require('./src/options');
const { isEncrypted, encrypt, decrypt, blindIndex, decryptLegacy } = require('./src/crypto');
const { userContextStore, getCurrentUserRole, canAccessField } = require('./src/access');
const { OptionsError, DecryptionError, UnsupportedOperatorError } = require('./src/errors');
const { createFilterRewriter } = require('./src/query');

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
 * - [validAccessData] bool - defaults to false. If true, values are decrypted only when allowed by `userContextStore`
 *
 * @param {Schema} schema - The mongoose schema
 * @param {Object} options - The plugin options
 */
const MongooseEncryptPlugin = function (schema, options) {
    options = normalizeOptions(options);

    const hashValue = (value) => blindIndex(value, options.hashKey);

    /**
     * Prepare a value for storage: its ciphertext and its search hash.
     * A value that is already encrypted is kept as is, so it is never encrypted twice.
     */
    function protect(value, field) {
        if (isEncrypted(value)) {
            try {
                return { stored: value, hash: hashValue(decrypt(value, options.encryptionKey)) };
            } catch (error) {
                throw new DecryptionError(field, error);
            }
        }

        return { stored: encrypt(String(value), options.encryptionKey), hash: hashValue(value) };
    }

    /**
     * Decrypt a stored value. Plaintext values (data not encrypted yet) are returned unchanged.
     * @param {*} value - stored value
     * @param {string} field - field name, for error messages
     * @param {string} [iv] - iv of a value written by v1 (needs the `legacy` option)
     * @param {string} [onError] - 'throw' or 'keep'
     */
    function reveal(value, field, iv, onError = options.onDecryptError) {
        if (typeof value !== 'string' || value === '') {
            return value;
        }

        try {
            if (isEncrypted(value)) {
                return decrypt(value, options.encryptionKey);
            }

            if (iv && options.legacy) {
                return decryptLegacy(value, iv, options.legacy);
            }

            return value;
        } catch (error) {
            if (onError === 'keep') {
                return value;
            }

            throw new DecryptionError(field, error);
        }
    }

    options.fields.forEach(field => {
        if (schema.path(field)?.options?.unique) {
            throw new OptionsError(`Field "${field}" is encrypted, so "unique: true" on it has no effect. Use the plugin option "unique: ['${field}']" instead`);
        }
    });

    async function updateRecord() {
        const update = this.getUpdate();

        if (!update || Array.isArray(update)) {
            return;
        }

        const { hashField, ivField, fields } = options;
        const has = (obj, key) => obj && Object.prototype.hasOwnProperty.call(obj, key);

        fields.forEach(field => {
            if (!has(update, field) && !has(update.$set, field)) {
                return;
            }

            // Move a top-level value into $set so the plaintext can never stay next to the ciphertext.
            if (has(update, field)) {
                update.$set = { ...(update.$set || {}), [field]: update[field] };
                delete update[field];
            }

            const value = update.$set[field];

            update.$unset = { ...(update.$unset || {}), [`${ivField}.${field}`]: 1 };

            if (value === undefined || value === null || value === '') {
                // Value cleared: drop the stale hash so the old value can no longer be found.
                update.$unset[`${hashField}.${field}`] = 1;
                return;
            }

            const { stored, hash } = protect(value, field);

            update.$set[field] = stored;
            update.$set[`${hashField}.${field}`] = hash;
        });

        this.setUpdate(update);
    }

    const rewriteFilter = createFilterRewriter({
        fields: options.fields,
        hashField: options.hashField,
        haveDataNotEncrypt: options.haveDataNotEncrypt,
        hashValue,
    });

    /** Query middleware: conditions on encrypted fields are rewritten to target their search hash. */
    async function processFilter() {
        this.setQuery(rewriteFilter(this.getFilter()));
    }

    /** Query middleware: make sure hash / iv are loaded with an inclusion projection. */
    async function processProjection() {
        const projection = this.projection();

        if (!projection || typeof projection !== 'object') {
            return;
        }

        const values = Object.entries(projection)
            .filter(([key]) => key !== '_id')
            .map(([, value]) => value);

        const isExclusion = values.every(value => value === 0 || value === false);

        if (values.length && !isExclusion) {
            this.projection({ ...projection, [options.hashField]: 1, [options.ivField]: 1 });
        }
    }

    function customDataAggregate(data, canAccess) {
        const { hashField, ivField } = options;
        if (data?.hasOwnProperty(hashField)) {
            if (canAccess) {
                for (const field in data[hashField]) {
                    const iv = data?.[ivField]?.[field] || '';
                    data[field] = reveal(data[field], field, iv, undefined);
                }
            }

            delete data[hashField];
            delete data[ivField];
        }

        for (const field in data) {
            if (typeof (data[field]) == 'object' && !Array.isArray(data[field])) {
                data[field] = decryptDataObject(data[field], canAccess);
            }
            else if (typeof (data[field]) == 'object' && Array.isArray(data[field])) {
                // Foreach child
                for (let i = 0; i < data[field].length; i++) {
                    const tmpObject = decryptDataObject(data[field][i], canAccess);
                    data[field][i] = tmpObject;
                }
            }
        }
    }

    // Nested objects (e.g. from $lookup) may come from another collection with other keys:
    // a value that cannot be decrypted is kept as is.
    function decryptDataObject(data, canAccess) {
        const { hashField, ivField } = options;
        if (data?.hasOwnProperty(hashField)) {
            if (canAccess) {
                for (const field in data[hashField]) {
                    const iv = data?.[ivField]?.[field] || '';
                    data[field] = reveal(data[field], field, iv, 'keep');
                }
            }

            delete data[hashField];
            delete data[ivField];
        }

        return data;
    }

    schema.add({ [options.hashField]: mongoose.Schema.Types.Mixed, [options.ivField]: mongoose.Schema.Types.Mixed });

    options.unique.forEach(field => {
        schema.index({ [`${options.hashField}.${field}`]: 1 }, { unique: true, sparse: true });
    });

    schema.method('toJSON', function () {
        let that = this;
        const { hashField, ivField, hideIV, fields } = options;
        const record = that;
        const recordObject = record.toObject();

        if (hideIV) {
            delete recordObject[hashField];
            delete recordObject[ivField];

            for (const key in recordObject) {
                if (typeof (recordObject[key]) == 'object' && !Array.isArray(recordObject[key])) {
                    const dataChild = recordObject[key];

                    if (dataChild?.hasOwnProperty(hashField)) {
                        delete dataChild[hashField];
                        delete dataChild[ivField];
                    }
                }
            }
        }

        return recordObject;
    });

    const FILTER_OPERATIONS = [
        'find', 'findOne', 'countDocuments', 'distinct',
        'updateOne', 'updateMany', 'findOneAndUpdate',
        'replaceOne', 'findOneAndReplace',
        'deleteOne', 'deleteMany', 'findOneAndDelete',
    ];

    schema.pre(FILTER_OPERATIONS, processFilter);
    schema.pre(['find', 'findOne', 'findOneAndUpdate', 'findOneAndReplace', 'findOneAndDelete'], processProjection);
    schema.pre(['updateOne', 'updateMany', 'findOneAndUpdate'], updateRecord);

    // encrypt data (create, save) before document store in the database
    schema.pre('save', async function () {
        const doc = this;
        const { hashField, ivField, fields } = options;

        // Keep hash/iv of the fields that are not re-encrypted in this save.
        const hashData = doc.isNew ? {} : { ...(doc.get(hashField) || {}) };
        const ivData = doc.isNew ? {} : { ...(doc.get(ivField) || {}) };

        fields.forEach(field => {
            const value = doc.get(field);

            // An unchanged field that still holds the stored ciphertext
            // (e.g. the document was loaded without decryption rights): never encrypt it twice.
            if (!doc.isNew && !doc.isModified(field) && (isEncrypted(value) || ivData[field])) {
                return;
            }

            if (value === undefined || value === null || value === '') {
                // Value cleared: drop the stale hash so old values can no longer be found.
                delete hashData[field];
                delete ivData[field];
                return;
            }

            const { stored, hash } = protect(value, field);

            hashData[field] = hash;
            delete ivData[field];
            doc.set(field, stored);
        });

        doc.set(hashField, hashData);
        doc.set(ivField, ivData);
    });

    // Mongoose 7/8 call insertMany pre hooks with (next, docs), Mongoose 9 with (docs).
    // `docs` is the array (or single object) passed to Model.insertMany().
    schema.pre('insertMany', async function (arg0, arg1) {
        const input = typeof arg0 === 'function' ? arg1 : arg0;
        const docs = Array.isArray(input) ? input : (input && typeof input === 'object' ? [input] : []);
        const { hashField, fields } = options;

        for (const data of docs) {
            if (!data || typeof data !== 'object') {
                continue; // let Mongoose report invalid input
            }

            const hashData = {};

            fields.forEach(field => {
                const value = data[field];

                if (value === undefined || value === null || value === '') {
                    return;
                }

                const { stored, hash } = protect(value, field);

                hashData[field] = hash;
                data[field] = stored;
            });

            data[hashField] = hashData;
        }
    });

    schema.post('insertMany', async function (docs) {
        if (Array.isArray(docs) && docs.length) {
            const { ivField, fields } = options;
            const canAccess = canAccessField(options.validAccessData);

            for (let i = 0; i < docs.length; i++) {
                const doc = docs[i];

                fields.forEach(field => {
                    if (doc[field]) {
                        // Check if user has permission to access this field
                        if (canAccess) {
                            const iv = doc?.[ivField]?.[field] || '';
                            doc[field] = reveal(doc[field], field, iv);
                        }
                        // else not decrypt the field
                    }
                });
            }
        }
    })

    schema.post('aggregate', function (docs) {
        if (Array.isArray(docs) && docs.length) {
            const canAccess = canAccessField(options.validAccessData);

            for (const data of docs) {
                customDataAggregate(data, canAccess);
            }
        }
    });

    // encrypt data (create, save) before document store in the database
    schema.post('save', function (doc) {
        const { ivField, fields } = options;
        const canAccess = canAccessField(options.validAccessData);

        fields.forEach(field => {
            if (doc[field]) {
                // Check if user has permission to access this field
                if (canAccess) {
                    const iv = doc?.[ivField]?.[field] || '';
                    doc[field] = reveal(doc[field].toString(), field, iv);
                }
                // else not decrypt the field
            }
        });
    });

    // decrypt data when document return from mongoose query
    schema.post('init', function (doc) {
        const { hashField, ivField, fields } = options;
        const canAccess = canAccessField(options.validAccessData);

        if (canAccess) {
            fields.forEach(field => {
                if (doc[field]) {
                    const iv = doc?.[ivField]?.[field] || '';
                    doc[field] = reveal(doc[field].toString(), field, iv);
                }
            });
        }

        delete doc[hashField];
        delete doc[ivField];
    });
}

module.exports = {
    MongooseEncryptPlugin,
    userContextStore,
    getCurrentUserRole,
    OptionsError,
    DecryptionError,
    UnsupportedOperatorError,
};