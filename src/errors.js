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
    constructor(field, operator) {
        super(`Operator "${operator}" is not supported on encrypted field "${field}"; only equality ($eq, $ne, $in, $nin, $exists) is supported`);
        this.field = field;
        this.operator = operator;
    }
}

module.exports = { MongooseEncryptError, OptionsError, DecryptionError, UnsupportedOperatorError };
