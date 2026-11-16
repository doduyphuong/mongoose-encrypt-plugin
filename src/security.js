/**
 * Warn when the application runs a Mongoose release with known security advisories.
 *
 * Mongoose is a peer dependency: queries run through the application's Mongoose (`schema.base`).
 * npm refuses to install this package next to an older Mongoose 9, but other package managers only
 * warn, so the version is also checked at runtime.
 */

// Lowest patched release per major line (Mongoose advisories published November 2026:
// GHSA-8332-j7wj-wjw4, GHSA-gg4r-jv3p-qx3c, GHSA-6972-9mcm-vhwj, GHSA-wr5m-5jph-8m96).
const PATCHED_RELEASES = {
    9: '9.11.4',
};

const ADVISORIES = [
    'GHSA-8332-j7wj-wjw4',
    'GHSA-gg4r-jv3p-qx3c',
    'GHSA-6972-9mcm-vhwj',
    'GHSA-wr5m-5jph-8m96',
];

const WARNING_CODE = 'MONGOOSE_ENCRYPT_VULNERABLE_MONGOOSE';

const warnedVersions = new Set();

function parseVersion(version) {
    const match = /^v?(\d+)\.(\d+)\.(\d+)/.exec(String(version || '').trim());

    return match ? match.slice(1, 4).map(Number) : null;
}

function compareVersions(a, b) {
    for (let i = 0; i < 3; i++) {
        if (a[i] !== b[i]) return a[i] - b[i];
    }

    return 0;
}

/**
 * @param {string} version - a Mongoose version such as "9.11.0"
 * @returns {string|null} the lowest patched release for that major line, or null when the
 *   version is not affected (or is not a major line this package supports)
 */
function getPatchedMongooseVersion(version) {
    const parsed = parseVersion(version);
    const patched = parsed && PATCHED_RELEASES[parsed[0]];

    if (!patched) return null;

    // Pre-releases of the patched version are treated as patched.
    return compareVersions(parsed, parseVersion(patched)) < 0 ? patched : null;
}

/**
 * Emit a single `SecurityWarning` per vulnerable Mongoose version.
 * @param {string} version - the application's Mongoose version
 * @returns {boolean} true when a warning was emitted
 */
function warnIfVulnerableMongoose(version) {
    const patched = getPatchedMongooseVersion(version);

    if (!patched || warnedVersions.has(version)) return false;

    warnedVersions.add(version);
    process.emitWarning(
        `mongoose-encrypt-plugin: Mongoose ${version} has known security vulnerabilities `
        + `(${ADVISORIES.join(', ')}). Upgrade Mongoose to ${patched} or later.`,
        { type: 'SecurityWarning', code: WARNING_CODE }
    );

    return true;
}

module.exports = {
    PATCHED_RELEASES,
    WARNING_CODE,
    getPatchedMongooseVersion,
    warnIfVulnerableMongoose,
};
