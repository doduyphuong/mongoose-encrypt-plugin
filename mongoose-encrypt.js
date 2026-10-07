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

    const has = (obj, key) => Boolean(obj) && typeof obj === 'object' && Object.prototype.hasOwnProperty.call(obj, key);
    const isEncryptedPath = (path) => options.fields.some(f => path === f || String(path).startsWith(`${f}.`));
    const WRITE_HINT = 'only $set, $setOnInsert and $unset (or a plain value) can write an encrypted field';

    /** Reject an update pipeline that would write an encrypted field in plaintext. */
    function checkUpdatePipeline(pipeline) {
        for (const stage of pipeline) {
            for (const [op, spec] of Object.entries(stage || {})) {
                if (op === '$replaceRoot' || op === '$replaceWith') {
                    throw new UnsupportedOperatorError(options.fields.join(', '), `update pipeline ${op}`, WRITE_HINT);
                }

                const paths = op === '$unset' ? [].concat(spec) : Object.keys(spec || {});

                for (const path of paths) {
                    if (isEncryptedPath(path)) {
                        throw new UnsupportedOperatorError(path, `update pipeline ${op}`, WRITE_HINT);
                    }
                }
            }
        }
    }

    /** Encrypt the values an update writes to encrypted fields and keep their search hash in sync. */
    function encryptUpdate(update) {
        const { hashField, ivField, fields } = options;

        for (const [op, spec] of Object.entries(update)) {
            if (!op.startsWith('$') || !spec || typeof spec !== 'object') {
                continue;
            }

            for (const [path, value] of Object.entries(spec)) {
                const allowed = ['$set', '$setOnInsert', '$unset'].includes(op) && fields.includes(path);

                if ((isEncryptedPath(path) && !allowed) || (op === '$rename' && isEncryptedPath(String(value)))) {
                    throw new UnsupportedOperatorError(path, op, WRITE_HINT);
                }
            }
        }

        fields.forEach(field => {
            // Move a top-level value into $set so the plaintext can never stay next to the ciphertext.
            if (has(update, field)) {
                update.$set = { ...(update.$set || {}), [field]: update[field] };
                delete update[field];
            }

            if (has(update.$unset, field)) {
                update.$unset[`${hashField}.${field}`] = 1;
                update.$unset[`${ivField}.${field}`] = 1;
            }

            for (const op of ['$set', '$setOnInsert']) {
                if (!has(update[op], field)) {
                    continue;
                }

                const value = update[op][field];

                if (op === '$set') {
                    // A new v2 value never needs the iv of a v1 value.
                    update.$unset = { ...(update.$unset || {}), [`${ivField}.${field}`]: 1 };
                }

                if (value === undefined || value === null || value === '') {
                    if (op === '$set') {
                        // Value cleared: drop the stale hash so the old value can no longer be found.
                        update.$unset[`${hashField}.${field}`] = 1;
                    }
                    continue;
                }

                const { stored, hash } = protect(value, field);

                update[op][field] = stored;
                update[op][`${hashField}.${field}`] = hash;
            }
        });

        return update;
    }

    /** Query middleware for updateOne / updateMany / findOneAndUpdate. */
    async function updateRecord() {
        const update = this.getUpdate();

        if (Array.isArray(update)) {
            checkUpdatePipeline(update);
        } else if (update && typeof update === 'object') {
            this.setUpdate(encryptUpdate(update));
        }
    }

    /** Encrypt the encrypted fields of a whole document (insertMany, replaceOne, findOneAndReplace). */
    function encryptDocument(data) {
        const { hashField, ivField, fields } = options;
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

        if (has(data, ivField)) {
            delete data[ivField];
        }

        return data;
    }

    /** Query middleware for replaceOne / findOneAndReplace. */
    async function replaceRecord() {
        const replacement = this.getUpdate();

        if (replacement && typeof replacement === 'object' && !Array.isArray(replacement)) {
            this.setUpdate(encryptDocument(replacement));
        }
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

    /** Remove hashField / ivField from a plain object and from its direct children. */
    function stripInternalFields(ret) {
        const { hashField, ivField } = options;
        const strip = (obj) => {
            if (obj && typeof obj === 'object') {
                delete obj[hashField];
                delete obj[ivField];
            }
        };

        strip(ret);

        for (const value of Object.values(ret)) {
            if (Array.isArray(value)) {
                value.forEach(strip);
            } else {
                strip(value);
            }
        }

        return ret;
    }

    // Keep Mongoose's own toJSON (schema toJSON options, virtuals, transform), then hide the internal fields.
    const baseToJSON = mongoose.Document.prototype.toJSON;

    schema.method('toJSON', function (toJSONOptions) {
        const ret = baseToJSON.call(this, toJSONOptions);

        return options.hideIV && ret && typeof ret === 'object' ? stripInternalFields(ret) : ret;
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
    schema.pre(['replaceOne', 'findOneAndReplace'], replaceRecord);

    // Rewrite the leading $match stages of an aggregation so they can filter on encrypted fields.
    schema.pre('aggregate', async function () {
        const pipeline = this.pipeline();

        for (let i = 0; i < pipeline.length && pipeline[i] && pipeline[i].$match; i++) {
            pipeline[i] = { ...pipeline[i], $match: rewriteFilter(pipeline[i].$match) };
        }
    });

    // Fields whose stored value is v2 ciphertext while the document holds the decrypted value.
    // They are not "modified", so save() leaves them untouched in the database.
    const DECRYPTED = 'mongooseEncryptDecrypted';

    /** Decrypt the encrypted fields of a document in place, without marking them as modified. */
    function revealDocument(doc) {
        const { ivField, fields } = options;

        if (!canAccessField(options.validAccessData)) {
            return;
        }

        const decrypted = doc.$locals[DECRYPTED] || (doc.$locals[DECRYPTED] = new Set());

        fields.forEach(field => {
            const value = doc.get(field);

            if (typeof value !== 'string' || value === '') {
                return;
            }

            const wasV2 = isEncrypted(value);
            const iv = doc.get(ivField)?.[field] || '';

            doc.set(field, reveal(value, field, iv));

            if (wasV2) {
                // A value decrypted from v1 (legacy) stays modified so the next save re-encrypts it with v2.
                doc.unmarkModified(field);
                decrypted.add(field);
            }
        });
    }

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
            const unchanged = !doc.isNew && !doc.isModified(field);

            if (unchanged && (isEncrypted(value) || ivData[field] || doc.$locals[DECRYPTED]?.has(field))) {
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

    // Mongoose 9 calls insertMany pre hooks with the array (or single object) passed to Model.insertMany().
    schema.pre('insertMany', async function (docs) {
        const list = Array.isArray(docs) ? docs : (docs && typeof docs === 'object' ? [docs] : []);

        for (const data of list) {
            if (data && typeof data === 'object') {
                encryptDocument(data); // invalid input is reported by Mongoose
            }
        }
    });

    schema.post('insertMany', async function (docs) {
        if (!Array.isArray(docs)) {
            return;
        }

        for (const doc of docs) {
            if (doc instanceof mongoose.Document) {
                revealDocument(doc);
            } else if (doc && typeof doc === 'object' && canAccessField(options.validAccessData)) {
                // lean: true
                options.fields.forEach(field => {
                    doc[field] = reveal(doc[field], field);
                });
            }
        }
    });

    schema.post('aggregate', function (docs) {
        if (Array.isArray(docs) && docs.length) {
            const canAccess = canAccessField(options.validAccessData);

            for (const data of docs) {
                customDataAggregate(data, canAccess);
            }
        }
    });

    // decrypt the saved document so the caller gets plaintext back (when allowed)
    schema.post('save', function (doc) {
        revealDocument(doc);
    });

    // decrypt documents returned by queries (when allowed)
    schema.post('init', function (doc) {
        revealDocument(doc);
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