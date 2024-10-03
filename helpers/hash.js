const crypto = require('crypto');

function encryptStr(text, secretKey, algorithm) {
    if (!algorithm) {
        algorithm = 'aes-256-ctr';
    }

    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv(algorithm, secretKey, iv);
    const encrypted = Buffer.concat([cipher.update(text), cipher.final()]);

    return { iv: iv.toString('hex'), encrypted: encrypted.toString('hex') };
}

function decryptStr(valueHash, secretKey, algorithm) {
    if (!algorithm) {
        algorithm = 'aes-256-ctr';
    }

    const { iv, hash } = valueHash;
    const decipher = crypto.createDecipheriv(algorithm, secretKey, Buffer.from(iv, 'hex'));
    const decrypted = Buffer.concat([decipher.update(Buffer.from(hash, 'hex')), decipher.final()]);

    return decrypted.toString();
}

module.exports = {
    encryptStr,
    decryptStr
}