const mongoose = require('mongoose');
const { isEncrypted } = require('../crypto');
const { canAccessField } = require('../access');
const { DECRYPTED } = require('../codec');

// Operations whose filter can target an encrypted field.
const FILTER_OPERATIONS = [
    'find', 'findOne', 'countDocuments', 'distinct',
    'updateOne', 'updateMany', 'findOneAndUpdate',
    'replaceOne', 'findOneAndReplace',
    'deleteOne', 'deleteMany', 'findOneAndDelete',
];

const PROJECTION_OPERATIONS = ['find', 'findOne', 'findOneAndUpdate', 'findOneAndReplace', 'findOneAndDelete'];

/**
 * Middleware for every read: filter rewriting, projection, aggregate, decryption of returned documents, toJSON.
 * @param {import('mongoose').Schema} schema
 * @param {{ options: Object, codec: Object, rewriteFilter: Function }} ctx
 */
function registerReadHooks(schema, { options, codec, rewriteFilter }) {
    const { hashField, ivField, fields } = options;
    const { reveal } = codec;
    const allowed = () => canAccessField(options.validAccessData);

    // Conditions on encrypted fields target their search hash.
    schema.pre(FILTER_OPERATIONS, async function processFilter() {
        this.setQuery(rewriteFilter(this.getFilter()));
    });

    // An inclusion projection must also load hash / iv; an exclusion projection is left alone.
    schema.pre(PROJECTION_OPERATIONS, async function processProjection() {
        const projection = this.projection();

        if (!projection || typeof projection !== 'object') {
            return;
        }

        const values = Object.entries(projection)
            .filter(([key]) => key !== '_id')
            .map(([, value]) => value);

        const isExclusion = values.every(value => value === 0 || value === false);

        if (values.length && !isExclusion) {
            this.projection({ ...projection, [hashField]: 1, [ivField]: 1 });
        }
    });

    // The leading $match stages of an aggregation can filter on encrypted fields.
    schema.pre('aggregate', async function () {
        const pipeline = this.pipeline();

        for (let i = 0; i < pipeline.length && pipeline[i] && pipeline[i].$match; i++) {
            pipeline[i] = { ...pipeline[i], $match: rewriteFilter(pipeline[i].$match) };
        }
    });

    /** Decrypt the encrypted fields of a document in place, without marking them as modified. */
    function revealDocument(doc) {
        if (!allowed()) {
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

    /** Remove hashField / ivField from a plain object. */
    function strip(obj) {
        if (obj && typeof obj === 'object') {
            delete obj[hashField];
            delete obj[ivField];
        }

        return obj;
    }

    /** Decrypt an aggregation result (a plain object) in place. */
    function revealAggregateRow(row, canAccess) {
        if (!row || typeof row !== 'object') {
            return;
        }

        if (canAccess) {
            fields.forEach(field => {
                row[field] = reveal(row[field], field, row[ivField]?.[field]);
            });
        }

        strip(row);

        // Nested objects (e.g. from $lookup) may come from another collection with other keys:
        // only objects carrying a hashField are touched, and a value that cannot be decrypted is kept.
        for (const value of Object.values(row)) {
            for (const child of Array.isArray(value) ? value : [value]) {
                if (child && typeof child === 'object' && Object.prototype.hasOwnProperty.call(child, hashField)) {
                    if (canAccess) {
                        for (const field of Object.keys(child[hashField] || {})) {
                            child[field] = reveal(child[field], field, child[ivField]?.[field], 'keep');
                        }
                    }

                    strip(child);
                }
            }
        }
    }

    // decrypt documents returned by queries (when allowed)
    schema.post('init', function (doc) {
        revealDocument(doc);
    });

    // decrypt the saved document so the caller gets plaintext back (when allowed)
    schema.post('save', function (doc) {
        revealDocument(doc);
    });

    schema.post('insertMany', async function (docs) {
        if (!Array.isArray(docs)) {
            return;
        }

        for (const doc of docs) {
            if (doc instanceof mongoose.Document) {
                revealDocument(doc);
            } else if (doc && typeof doc === 'object' && allowed()) {
                // lean: true
                fields.forEach(field => {
                    doc[field] = reveal(doc[field], field);
                });
            }
        }
    });

    schema.post('aggregate', function (rows) {
        if (Array.isArray(rows) && rows.length) {
            const canAccess = allowed();

            rows.forEach(row => revealAggregateRow(row, canAccess));
        }
    });

    // Keep Mongoose's own toJSON (schema toJSON options, virtuals, transform), then hide the internal fields.
    // toObject() is left untouched: Mongoose uses it internally (clone, populate, save).
    const baseToJSON = mongoose.Document.prototype.toJSON;

    schema.method('toJSON', function (toJSONOptions) {
        const ret = baseToJSON.call(this, toJSONOptions);

        if (!options.hideIV || !ret || typeof ret !== 'object') {
            return ret;
        }

        strip(ret);

        for (const value of Object.values(ret)) {
            (Array.isArray(value) ? value : [value]).forEach(strip);
        }

        return ret;
    });
}

module.exports = { registerReadHooks, FILTER_OPERATIONS };
