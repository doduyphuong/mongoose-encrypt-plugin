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
 *
 * @param {Object} ctx
 * @param {string[]} ctx.fields - encrypted fields
 * @param {string} ctx.hashField
 * @param {boolean} ctx.haveDataNotEncrypt
 * @param {(value: *) => string} ctx.hashValue
 */
function createFilterRewriter({ fields, hashField, haveDataNotEncrypt, hashValue }) {
    const hashOf = (value) => (value === null || value === undefined ? value : hashValue(value));

    /** Rewrite one operator (or a plain value) of an encrypted field into a condition on its hash. */
    function hashCondition(field, op, value) {
        switch (op) {
            case null:
            case '$eq':
            case '$ne':
                if (value instanceof RegExp) {
                    throw new UnsupportedOperatorError(field, '$regex');
                }
                return op ? { [op]: hashOf(value) } : hashOf(value);
            case '$in':
            case '$nin':
                if (!Array.isArray(value)) {
                    throw new UnsupportedOperatorError(field, `${op} (expects an array)`);
                }
                if (value.some(v => v instanceof RegExp)) {
                    throw new UnsupportedOperatorError(field, '$regex');
                }
                return { [op]: value.map(hashOf) };
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

        if (!haveDataNotEncrypt) {
            const merged = {};
            let plain;

            for (const [op, value] of parts) {
                const hashed = hashCondition(field, op, value);

                if (op === null) {
                    plain = hashed;
                } else {
                    Object.assign(merged, hashed);
                }
            }

            if (plain !== undefined) {
                return Object.keys(merged).length
                    ? [{ [hashPath]: plain }, { [hashPath]: merged }]
                    : [{ [hashPath]: plain }];
            }

            return [{ [hashPath]: merged }];
        }

        return parts.map(([op, value]) => {
            const hashed = hashCondition(field, op, value);
            const raw = op === null ? value : { [op]: value };

            if (op === '$exists') {
                // Encrypted and plaintext documents both store the field itself.
                return { [field]: raw };
            }

            const either = [{ [field]: raw }, { [hashPath]: hashed }];

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

module.exports = { createFilterRewriter, isOperatorObject, POSITIVE_OPERATORS, NEGATIVE_OPERATORS };
