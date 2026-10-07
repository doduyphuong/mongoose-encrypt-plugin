const { AsyncLocalStorage } = require('async_hooks');

// Async context holding the decryption rights of the current request: { isShowDecrypted: boolean }
const userContextStore = new AsyncLocalStorage();

/**
 * Whether the current async context asked for decrypted values.
 * @returns {boolean}
 */
function getCurrentUserRole() {
    const context = userContextStore.getStore();

    return context?.isShowDecrypted || false;
}

/**
 * Check if the current async context is allowed to see decrypted data.
 * When `validAccessData` is false (default) data is always decrypted.
 * When it is true, data is decrypted only inside `userContextStore.run({ isShowDecrypted: true }, ...)`.
 * @param {boolean} validAccessData - the plugin option `validAccessData`
 * @returns {boolean}
 */
function canAccessField(validAccessData) {
    return validAccessData ? getCurrentUserRole() : true;
}

module.exports = { userContextStore, getCurrentUserRole, canAccessField };
