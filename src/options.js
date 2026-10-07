const { OptionsError } = require('./errors');

const KEY_BYTES = 32;
const LEGACY_ALGORITHMS = ['aes-256-ctr', 'aes-256-cbc'];

/**
 * Turn a key option into a 32-byte Buffer.
 * Accepts a Buffer, a 64-char hex string, a base64 string, or (for keys written for v1) a 32-byte UTF-8 string.
 * @param {Buffer|string} value
 * @param {string} name - option name used in error messages
 * @returns {Buffer}
 */
function parseKey(value, name) {
    if (value === undefined || value === null || value === '') {
        throw new OptionsError(`Option "${name}" is required: a 32-byte key (Buffer, 64-char hex or base64 string)`);
    }

    let key;

    if (Buffer.isBuffer(value)) {
        key = value;
    } else if (typeof value === 'string') {
        if (/^[0-9a-f]{64}$/i.test(value)) {
            key = Buffer.from(value, 'hex');
        } else if (/^[A-Za-z0-9+/]{43}=$/.test(value)) {
            key = Buffer.from(value, 'base64');
        } else {
            key = Buffer.from(value, 'utf8');
        }
    } else {
        throw new OptionsError(`Option "${name}" must be a Buffer or a string`);
    }

    if (key.length !== KEY_BYTES) {
        throw new OptionsError(`Option "${name}" must be 32 bytes, got ${key.length} bytes. Generate one with crypto.randomBytes(32).toString('base64')`);
    }

    return key;
}

/**
 * Validate the plugin options and apply defaults.
 * @param {Object} options - options passed to schema.plugin()
 * @returns {Object} normalized options (keys as Buffers)
 */
function normalizeOptions(options = {}) {
    const { fields } = options;

    if (!Array.isArray(fields) || !fields.length || fields.some(f => typeof f !== 'string' || !f)) {
        throw new OptionsError('Option "fields" must be a non-empty array of field names');
    }

    if (options.salt !== undefined && options.encryptionKey === undefined) {
        throw new OptionsError('Option "salt" was replaced in v2 by "encryptionKey" and "hashKey". Pass the old salt as "legacy: { salt }" to keep reading data written by v1');
    }

    if (options.algorithm !== undefined) {
        throw new OptionsError('Option "algorithm" was removed in v2: data is always encrypted with AES-256-GCM. Use "legacy: { salt, algorithm }" for data written by v1');
    }

    const encryptionKey = parseKey(options.encryptionKey, 'encryptionKey');
    const hashKey = parseKey(options.hashKey, 'hashKey');

    if (encryptionKey.equals(hashKey)) {
        throw new OptionsError('Options "encryptionKey" and "hashKey" must be different keys');
    }

    let legacy = null;

    if (options.legacy) {
        const algorithm = options.legacy.algorithm || 'aes-256-ctr';

        if (!LEGACY_ALGORITHMS.includes(algorithm)) {
            throw new OptionsError(`Option "legacy.algorithm" must be one of ${LEGACY_ALGORITHMS.join(', ')}`);
        }

        legacy = { key: parseKey(options.legacy.salt, 'legacy.salt'), algorithm };
    }

    const unique = options.unique || [];

    if (!Array.isArray(unique) || unique.some(f => !fields.includes(f))) {
        throw new OptionsError('Option "unique" must be an array of names listed in "fields"');
    }

    const onDecryptError = options.onDecryptError || 'throw';

    if (!['throw', 'keep'].includes(onDecryptError)) {
        throw new OptionsError('Option "onDecryptError" must be "throw" or "keep"');
    }

    return {
        hashField: 'hashField',
        ivField: 'ivField',
        hideIV: true,
        haveDataNotEncrypt: false,
        validAccessData: false,
        ...options,
        encryptionKey,
        hashKey,
        legacy,
        unique,
        onDecryptError,
    };
}

module.exports = { normalizeOptions, parseKey };
