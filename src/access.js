const { AsyncLocalStorage } = require('async_hooks');

// Async context holding the decryption rights of the current request: { isShowDecrypted: boolean }
const userContextStore = new AsyncLocalStorage();

/**
 * Whether the current async context asked for decrypted values.
 * @returns {boolean}
 */
function isDecryptionAllowed() {
    const context = userContextStore.getStore();

    return context?.isShowDecrypted === true;
}

/**
 * @deprecated since 2.0.0, use `isDecryptionAllowed()`.
 * @returns {boolean}
 */
function getCurrentUserRole() {
    return isDecryptionAllowed();
}

/**
 * Run `fn` with the given decryption rights. Queries are awaited inside the context,
 * so lazy Mongoose queries (`() => Model.find()`) work as expected.
 *
 *      const user = await runWithDecryption(true, () => User.findById(id));
 *
 * @template T
 * @param {boolean} isShowDecrypted
 * @param {() => T | Promise<T>} fn
 * @returns {Promise<Awaited<T>>}
 */
function runWithDecryption(isShowDecrypted, fn) {
    return userContextStore.run({ isShowDecrypted: Boolean(isShowDecrypted) }, async () => await fn());
}

/**
 * Check if the current async context is allowed to see decrypted data.
 * When `validAccessData` is false (default) data is always decrypted.
 * When it is true, data is decrypted only inside `runWithDecryption(true, ...)`.
 * @param {boolean} validAccessData - the plugin option `validAccessData`
 * @returns {boolean}
 */
function canAccessField(validAccessData) {
    return validAccessData ? isDecryptionAllowed() : true;
}

module.exports = { userContextStore, isDecryptionAllowed, getCurrentUserRole, runWithDecryption, canAccessField };
