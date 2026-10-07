class MongooseEncryptError extends Error {
    constructor(message) {
        super(message);
        this.name = this.constructor.name;
    }
}

/** Invalid plugin options (thrown when the plugin is applied to a schema). */
class OptionsError extends MongooseEncryptError {}

/** A stored value could not be decrypted (wrong key, tampered or corrupted data). */
class DecryptionError extends MongooseEncryptError {
    constructor(field, cause) {
        super(`Cannot decrypt field "${field}": the value was tampered with, is corrupted or was encrypted with another key`);
        this.field = field;
        this.cause = cause;
    }
}

/** A query or update uses an operator that cannot work on an encrypted field. */
class UnsupportedOperatorError extends MongooseEncryptError {
    /**
     * @param {string} field - encrypted field (or path) the operator was used on
     * @param {string} operator
     * @param {string} [hint] - what is supported instead
     */
    constructor(field, operator, hint = 'only equality ($eq, $ne, $in, $nin, $exists) is supported') {
        super(`Operator "${operator}" is not supported on encrypted field "${field}"; ${hint}`);
        this.field = field;
        this.operator = operator;
    }
}

module.exports = { MongooseEncryptError, OptionsError, DecryptionError, UnsupportedOperatorError };
