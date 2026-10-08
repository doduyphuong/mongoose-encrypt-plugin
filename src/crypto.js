const crypto = require('crypto');

const ALGORITHM = 'aes-256-gcm';
const PREFIX = 'v2:';
const IV_BYTES = 12;
const TAG_BYTES = 16;

/** True when `value` is a v2 ciphertext produced by `encrypt()`. */
function isEncrypted(value) {
    return typeof value === 'string' && value.startsWith(PREFIX);
}

/**
 * Encrypt a string with AES-256-GCM.
 * @param {string} plaintext
 * @param {Buffer} key - 32 bytes
 * @returns {string} `v2:<iv hex>:<auth tag hex>:<ciphertext hex>`
 */
function encrypt(plaintext, key) {
    const iv = crypto.randomBytes(IV_BYTES);
    const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
    const encrypted = Buffer.concat([cipher.update(String(plaintext), 'utf8'), cipher.final()]);
    const tag = cipher.getAuthTag();

    return `${PREFIX}${iv.toString('hex')}:${tag.toString('hex')}:${encrypted.toString('hex')}`;
}

/**
 * Decrypt a value produced by `encrypt()`. Throws when the value was tampered with or the key is wrong.
 * @param {string} value
 * @param {Buffer} key - 32 bytes
 * @returns {string}
 */
function decrypt(value, key) {
    const parts = value.slice(PREFIX.length).split(':');

    if (parts.length !== 3) {
        throw new Error('Malformed ciphertext');
    }

    const [ivHex, tagHex, dataHex] = parts;
    const iv = Buffer.from(ivHex, 'hex');
    const tag = Buffer.from(tagHex, 'hex');

    if (iv.length !== IV_BYTES || tag.length !== TAG_BYTES) {
        throw new Error('Malformed ciphertext');
    }

    const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
    decipher.setAuthTag(tag);

    return Buffer.concat([decipher.update(Buffer.from(dataHex, 'hex')), decipher.final()]).toString('utf8');
}

/**
 * Keyed hash used to search encrypted fields by equality (blind index).
 * @param {*} value - converted with String()
 * @param {Buffer} key - 32 bytes, different from the encryption key
 * @returns {string} base64 HMAC-SHA256
 */
function blindIndex(value, key) {
    return crypto.createHmac('sha256', key).update(String(value), 'utf8').digest('base64');
}

/**
 * Search hash written by plugin v1 (unkeyed SHA-256). Only used to find v1 documents until they are migrated.
 * @param {*} value - converted with String()
 * @returns {string} base64 SHA-256
 */
function legacyHash(value) {
    return crypto.createHash('sha256').update(String(value), 'utf8').digest('base64');
}

/**
 * Decrypt a value written by plugin v1 (AES-256-CTR/CBC, iv stored in `ivField`).
 * @param {string} value - hex ciphertext
 * @param {string} iv - hex iv
 * @param {{ key: Buffer, algorithm: string }} legacy
 */
function decryptLegacy(value, iv, legacy) {
    const decipher = crypto.createDecipheriv(legacy.algorithm, legacy.key, Buffer.from(iv, 'hex'));

    return Buffer.concat([decipher.update(Buffer.from(value, 'hex')), decipher.final()]).toString();
}

module.exports = { PREFIX, isEncrypted, encrypt, decrypt, blindIndex, legacyHash, decryptLegacy };
