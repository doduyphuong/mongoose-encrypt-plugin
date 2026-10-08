const { isEncrypted, encrypt, decrypt, blindIndex, legacyHash, decryptLegacy } = require('./crypto');
const { DecryptionError } = require('./errors');

/** `doc.$locals` key: fields holding a decrypted value whose stored value is unchanged v2 ciphertext. */
const DECRYPTED = 'mongooseEncryptDecrypted';

/**
 * Encryption helpers bound to the options of one schema.
 * @param {Object} options - normalized plugin options
 */
function createCodec(options) {
    const hashValue = (value) => blindIndex(value, options.hashKey);

    // While data written by v1 is being migrated, a stored hash can still be its v1 SHA-256.
    const hashValues = (value) => (options.legacy ? [hashValue(value), legacyHash(value)] : [hashValue(value)]);

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

    return { hashValue, hashValues, protect, reveal };
}

module.exports = { createCodec, DECRYPTED };
