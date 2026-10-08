const { isEncrypted, encrypt, decryptLegacy } = require('./crypto');
const { OptionsError, DecryptionError } = require('./errors');

/**
 * Add `Model.migrateEncryption()` to a schema using the plugin.
 * @param {import('mongoose').Schema} schema
 * @param {{ options: Object, codec: Object }} ctx
 */
function registerMigration(schema, { options, codec }) {
    /**
     * Re-encrypt, in batches, the documents still holding values written by plugin v1 (or plaintext).
     * Works directly on the collection: no middleware, no decryption rights needed. Safe to run again.
     * Exposed as `Model.migrateEncryption(opts)` and `migrateV1(Model, opts)`.
     *
     * @param {Object} [opts]
     * @param {number} [opts.batchSize=500]
     * @param {boolean} [opts.dryRun=false] - count and check only, write nothing
     * @param {boolean} [opts.includePlaintext=false] - also encrypt values still stored in plaintext
     * @param {(stats: Object) => void} [opts.onProgress] - called after each batch
     * @returns {Promise<{ scanned: number, migrated: number, failed: Array<{ _id: *, field: string, error: string }>, dryRun: boolean }>}
     */
    schema.static('migrateEncryption', async function migrateEncryption(opts = {}) {
        const { batchSize = 500, dryRun = false, includePlaintext = false, onProgress } = opts;
        const { hashField, ivField, fields, legacy } = options;

        if (!legacy && !includePlaintext) {
            throw new OptionsError('Migrating data written by v1 needs the "legacy: { salt, algorithm }" option (or includePlaintext: true)');
        }

        const pending = [{ [ivField]: { $exists: true } }];

        if (includePlaintext) {
            fields.forEach(field => {
                pending.push({ [field]: { $type: 'string', $ne: '' }, [`${hashField}.${field}`]: { $exists: false } });
            });
        }

        const stats = { scanned: 0, migrated: 0, failed: [], dryRun };
        let lastId = null;

        for (;;) {
            const filter = { $or: pending };

            if (lastId !== null) {
                filter._id = { $gt: lastId };
            }

            const docs = await this.collection.find(filter).sort({ _id: 1 }).limit(batchSize).toArray();

            if (!docs.length) {
                break;
            }

            const operations = [];

            for (const doc of docs) {
                const $set = {};
                const guard = { _id: doc._id };

                try {
                    for (const field of fields) {
                        const value = doc[field];

                        if (typeof value !== 'string' || value === '' || isEncrypted(value)) {
                            continue;
                        }

                        const iv = doc[ivField]?.[field];

                        if (!iv && !includePlaintext) {
                            continue;
                        }

                        let plain;

                        try {
                            plain = iv ? decryptLegacy(value, iv, legacy) : value;
                        } catch (error) {
                            throw new DecryptionError(field, error);
                        }

                        $set[field] = encrypt(plain, options.encryptionKey);
                        $set[`${hashField}.${field}`] = codec.hashValue(plain);
                        guard[field] = value; // skip the document if it changed meanwhile
                    }
                } catch (error) {
                    stats.failed.push({ _id: doc._id, field: error.field, error: error.message });
                    continue;
                }

                const update = {};

                if (Object.keys($set).length) {
                    update.$set = $set;
                }

                if (doc[ivField] !== undefined) {
                    update.$unset = { [ivField]: 1 };
                }

                if (Object.keys(update).length) {
                    operations.push({ updateOne: { filter: guard, update } });
                }
            }

            stats.scanned += docs.length;
            stats.migrated += operations.length;

            if (!dryRun && operations.length) {
                await this.collection.bulkWrite(operations, { ordered: false });
            }

            lastId = docs.at(-1)._id;

            if (onProgress) {
                onProgress({ ...stats, failed: [...stats.failed] });
            }
        }

        return stats;
    });
}

/**
 * Re-encrypt the documents of `Model` still holding values written by plugin v1.
 * @param {import('mongoose').Model} Model - a model whose schema uses MongooseEncryptPlugin with the `legacy` option
 * @param {Object} [opts] - see `Model.migrateEncryption()`
 */
function migrateV1(Model, opts) {
    if (typeof Model?.migrateEncryption !== 'function') {
        throw new OptionsError('migrateV1() expects a model whose schema uses MongooseEncryptPlugin');
    }

    return Model.migrateEncryption(opts);
}

module.exports = { registerMigration, migrateV1 };
