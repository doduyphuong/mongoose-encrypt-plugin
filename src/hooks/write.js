const { isEncrypted } = require('../crypto');
const { UnsupportedOperatorError } = require('../errors');
const { DECRYPTED } = require('../codec');

const WRITE_HINT = 'only $set, $setOnInsert and $unset (or a plain value) can write an encrypted field';

const has = (obj, key) => Boolean(obj) && typeof obj === 'object' && Object.prototype.hasOwnProperty.call(obj, key);
const isEmpty = (value) => value === undefined || value === null || value === '';

/**
 * Middleware that encrypts every write: save, insertMany, update queries, replace queries and bulkWrite.
 * @param {import('mongoose').Schema} schema
 * @param {{ options: Object, codec: Object, rewriteFilter: Function }} ctx
 */
function registerWriteHooks(schema, { options, codec, rewriteFilter }) {
    const { hashField, ivField, fields } = options;
    const { protect } = codec;
    const isEncryptedPath = (path) => fields.some(f => path === f || String(path).startsWith(`${f}.`));

    /** Reject an update pipeline that would write an encrypted field in plaintext. */
    function checkUpdatePipeline(pipeline) {
        for (const stage of pipeline) {
            for (const [op, spec] of Object.entries(stage || {})) {
                if (op === '$replaceRoot' || op === '$replaceWith') {
                    throw new UnsupportedOperatorError(fields.join(', '), `update pipeline ${op}`, WRITE_HINT);
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

        // An update that already writes hashField / ivField as a whole (e.g. Model.bulkSave()) must not
        // also write their sub-paths: MongoDB rejects conflicting paths.
        const writesWholeHash = (op) => has(update[op], hashField);
        const writesWholeIv = has(update.$set, ivField) || has(update.$unset, ivField);

        fields.forEach(field => {
            // Move a top-level value into $set so the plaintext can never stay next to the ciphertext.
            if (has(update, field)) {
                update.$set = { ...(update.$set || {}), [field]: update[field] };
                delete update[field];
            }

            if (has(update.$unset, field)) {
                if (!writesWholeHash('$set') && !has(update.$unset, hashField)) {
                    update.$unset[`${hashField}.${field}`] = 1;
                }
                if (!writesWholeIv) {
                    update.$unset[`${ivField}.${field}`] = 1;
                }
            }

            for (const op of ['$set', '$setOnInsert']) {
                if (!has(update[op], field)) {
                    continue;
                }

                const value = update[op][field];

                if (op === '$set' && !writesWholeIv) {
                    // A new v2 value never needs the iv of a v1 value.
                    update.$unset = { ...(update.$unset || {}), [`${ivField}.${field}`]: 1 };
                }

                if (isEmpty(value)) {
                    if (op === '$set' && !writesWholeHash('$set')) {
                        // Value cleared: drop the stale hash so the old value can no longer be found.
                        update.$unset = { ...(update.$unset || {}), [`${hashField}.${field}`]: 1 };
                    }
                    continue;
                }

                const { stored, hash } = protect(value, field);

                update[op][field] = stored;

                if (!writesWholeHash(op)) {
                    update[op][`${hashField}.${field}`] = hash;
                }
            }
        });

        return update;
    }

    /** Encrypt the encrypted fields of a whole document (insertMany, replace, bulkWrite insertOne). */
    function encryptDocument(data) {
        const hashData = {};

        fields.forEach(field => {
            const value = data[field];

            if (isEmpty(value)) {
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

    // updateOne / updateMany / findOneAndUpdate
    schema.pre(['updateOne', 'updateMany', 'findOneAndUpdate'], async function updateRecord() {
        const update = this.getUpdate();

        if (Array.isArray(update)) {
            checkUpdatePipeline(update);
        } else if (update && typeof update === 'object') {
            this.setUpdate(encryptUpdate(update));
        }
    });

    // replaceOne / findOneAndReplace
    schema.pre(['replaceOne', 'findOneAndReplace'], async function replaceRecord() {
        const replacement = this.getUpdate();

        if (replacement && typeof replacement === 'object' && !Array.isArray(replacement)) {
            this.setUpdate(encryptDocument(replacement));
        }
    });

    // create / save
    schema.pre('save', async function () {
        const doc = this;

        // Keep hash/iv of the fields that are not re-encrypted in this save.
        const hashData = doc.isNew ? {} : { ...(doc.get(hashField) || {}) };
        const ivData = doc.isNew ? {} : { ...(doc.get(ivField) || {}) };

        fields.forEach(field => {
            const value = doc.get(field);

            // An unchanged field that still holds the stored ciphertext (e.g. loaded without decryption
            // rights) or whose stored value is unchanged v2 ciphertext: never encrypt it again.
            const unchanged = !doc.isNew && !doc.isModified(field);

            if (unchanged && (isEncrypted(value) || ivData[field] || doc.$locals[DECRYPTED]?.has(field))) {
                return;
            }

            if (isEmpty(value)) {
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
        // ivField only exists while the document still holds values written by v1.
        doc.set(ivField, Object.keys(ivData).length ? ivData : undefined);
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

    // Model.bulkWrite() (and Model.bulkSave(), which calls it): encrypt every operation and rewrite its filter.
    schema.pre('bulkWrite', async function (ops) {
        if (!Array.isArray(ops)) {
            return;
        }

        for (const op of ops) {
            if (!op || typeof op !== 'object') {
                continue;
            }

            if (op.insertOne?.document) {
                encryptDocument(op.insertOne.document);
            }

            for (const kind of ['updateOne', 'updateMany']) {
                if (op[kind]) {
                    op[kind].filter = rewriteFilter(op[kind].filter);

                    if (Array.isArray(op[kind].update)) {
                        checkUpdatePipeline(op[kind].update);
                    } else if (op[kind].update && typeof op[kind].update === 'object') {
                        encryptUpdate(op[kind].update);
                    }
                }
            }

            if (op.replaceOne) {
                op.replaceOne.filter = rewriteFilter(op.replaceOne.filter);

                if (op.replaceOne.replacement && typeof op.replaceOne.replacement === 'object') {
                    encryptDocument(op.replaceOne.replacement);
                }
            }

            for (const kind of ['deleteOne', 'deleteMany']) {
                if (op[kind]) {
                    op[kind].filter = rewriteFilter(op[kind].filter);
                }
            }
        }
    });
}

module.exports = { registerWriteHooks };
