const { UnsupportedOperatorError } = require('./errors');

const LOGICAL_OPERATORS = ['$and', '$or', '$nor'];
const POSITIVE_OPERATORS = ['$eq', '$in'];
const NEGATIVE_OPERATORS = ['$ne', '$nin'];

/** A plain `{ $op: value }` object (not a value such as a Date, ObjectId or Buffer). */
function isOperatorObject(value) {
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
        return false;
    }

    const proto = Object.getPrototypeOf(value);
    const keys = Object.keys(value);

    return (proto === Object.prototype || proto === null) && keys.length > 0 && keys.every(k => k.startsWith('$'));
}

/** Copy the symbol markers of `source` (such as the one set by `mongoose.trusted()`) onto `target`. */
function carryMarkers(source, target) {
    if (source && typeof source === 'object' && target && typeof target === 'object') {
        for (const symbol of Object.getOwnPropertySymbols(source)) {
            target[symbol] = source[symbol];
        }
    }

    return target;
}

/**
 * Build a function that rewrites a MongoDB filter so conditions on encrypted fields
 * target their search hash (`<hashField>.<field>`).
 *
 * - `$and` / `$or` / `$nor` are rewritten recursively and keep their meaning.
 * - Supported on encrypted fields: value, `$eq`, `$ne`, `$in`, `$nin`, `$exists`.
 *   `$exists: true` matches documents that store a non-empty value.
 * - Anything else (`$regex`, RegExp, `$gt`, `$not`, ...) throws `UnsupportedOperatorError`.
 * - With `haveDataNotEncrypt`, each condition also matches the plaintext value, grouped in its own
 *   `$or` (or `$and` for `$ne` / `$nin`) so it is still ANDed with the rest of the filter.
 * - `sanitizeFilter` keeps working: a condition wrapped in `mongoose.trusted()` stays trusted, and the
 *   operators the plugin builds from a plain value or a lone `$eq` (which `sanitizeFilter` lets through)
 *   are marked trusted, since they only hold hashes computed by the plugin. Any other operator sent by
 *   a user is left untrusted, so `sanitizeFilter` still neutralises it.
 *
 * @param {Object} ctx
 * @param {string[]} ctx.fields - encrypted fields
 * @param {string} ctx.hashField
 * @param {boolean} ctx.haveDataNotEncrypt
 * @param {(value: *) => string[]} ctx.hashValues - every hash a stored value may have
 *   (the v2 HMAC, plus the v1 SHA-256 while data written by v1 is being migrated)
 * @param {(obj: Object) => Object} [ctx.trusted] - marks an object as trusted (`mongoose.trusted`)
 */
function createFilterRewriter({ fields, hashField, haveDataNotEncrypt, hashValues, trusted = (obj) => obj }) {
    const hashesOf = (value) => (value === null || value === undefined ? [value] : hashValues(value));

    /** Rewrite one operator (or a plain value) of an encrypted field into a condition on its hash. */
    function hashCondition(field, op, value) {
        switch (op) {
            case null:
            case '$eq':
            case '$ne': {
                if (value instanceof RegExp) {
                    throw new UnsupportedOperatorError(field, '$regex');
                }

                const hashes = hashesOf(value);

                if (op === '$ne') {
                    return hashes.length === 1 ? { $ne: hashes[0] } : { $nin: hashes };
                }

                if (hashes.length > 1) {
                    return { $in: hashes };
                }

                return op ? { $eq: hashes[0] } : hashes[0];
            }
            case '$in':
            case '$nin':
                if (!Array.isArray(value)) {
                    throw new UnsupportedOperatorError(field, `${op} (expects an array)`);
                }
                if (value.some(v => v instanceof RegExp)) {
                    throw new UnsupportedOperatorError(field, '$regex');
                }
                return { [op]: value.flatMap(hashesOf) };
            case '$exists':
                return { $exists: Boolean(value) };
            default:
                throw new UnsupportedOperatorError(field, op);
        }
    }

    /** Split a condition into single-operator parts: [[op, value], ...]; op null = plain equality. */
    function splitCondition(field, condition) {
        if (condition instanceof RegExp) {
            throw new UnsupportedOperatorError(field, '$regex');
        }

        return isOperatorObject(condition) ? Object.entries(condition) : [[null, condition]];
    }

    /** Clauses (to be ANDed) that replace `{ [field]: condition }`. */
    function rewriteField(field, condition) {
        const hashPath = `${hashField}.${field}`;
        const parts = splitCondition(field, condition);
        // `sanitizeFilter` lets a plain value or a lone `$eq` through as it is.
        const passesSanitize = parts.length === 1 && (parts[0][0] === null || parts[0][0] === '$eq');
        const hashed = (op, value) => {
            const result = carryMarkers(condition, hashCondition(field, op, value));

            return passesSanitize && result && typeof result === 'object' ? trusted(result) : result;
        };

        if (!haveDataNotEncrypt) {
            // One clause per operator: two operators can map to the same one on the hash ($eq and $in -> $in).
            return parts.map(([op, value]) => ({ [hashPath]: hashed(op, value) }));
        }

        return parts.map(([op, value]) => {
            const hashedCondition = hashed(op, value);
            const raw = op === null ? value : carryMarkers(condition, { [op]: value });

            if (op === '$exists') {
                // Encrypted and plaintext documents both store the field itself.
                return { [field]: raw };
            }

            const either = [{ [field]: raw }, { [hashPath]: hashedCondition }];

            return NEGATIVE_OPERATORS.includes(op) ? { $and: either } : { $or: either };
        });
    }

    /**
     * @param {Object} filter - a MongoDB filter
     * @returns {Object} a new filter (the input is not modified)
     */
    function rewriteFilter(filter) {
        if (!filter || typeof filter !== 'object' || Array.isArray(filter)) {
            return filter;
        }

        const out = {};
        const extra = [];

        for (const [key, condition] of Object.entries(filter)) {
            if (LOGICAL_OPERATORS.includes(key) && Array.isArray(condition)) {
                out[key] = condition.map(rewriteFilter);
            } else if (fields.includes(key)) {
                extra.push(...rewriteField(key, condition));
            } else {
                out[key] = condition;
            }
        }

        if (!extra.length) {
            return out;
        }

        // A single clause on a new path can stay top-level; otherwise AND everything explicitly.
        if (extra.length === 1) {
            const [path] = Object.keys(extra[0]);

            if (!(path in out) && !path.startsWith('$')) {
                return { ...out, ...extra[0] };
            }
        }

        return { ...out, $and: [...(out.$and || []), ...extra] };
    }

    return rewriteFilter;
}

module.exports = { createFilterRewriter, isOperatorObject, carryMarkers, POSITIVE_OPERATORS, NEGATIVE_OPERATORS };
