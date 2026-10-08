const { MongooseEncryptPlugin } = require('./src/plugin');
const { migrateV1 } = require('./src/migrate');
const { userContextStore, isDecryptionAllowed, getCurrentUserRole, runWithDecryption } = require('./src/access');
const { MongooseEncryptError, OptionsError, DecryptionError, UnsupportedOperatorError } = require('./src/errors');

module.exports = {
    MongooseEncryptPlugin,
    migrateV1,
    userContextStore,
    runWithDecryption,
    isDecryptionAllowed,
    getCurrentUserRole,
    MongooseEncryptError,
    OptionsError,
    DecryptionError,
    UnsupportedOperatorError,
};
