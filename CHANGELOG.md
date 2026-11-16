# Changelog

## 1.1.11 - 2026-11-16

### Security

- The plugin emits a `SecurityWarning` (code `MONGOOSE_ENCRYPT_VULNERABLE_MONGOOSE`) once per process when it is applied to a schema of a Mongoose release with known vulnerabilities: 7.x before 7.8.13 and 8.x before 8.24.7 ([GHSA-8332-j7wj-wjw4](https://github.com/advisories/GHSA-8332-j7wj-wjw4), [GHSA-gg4r-jv3p-qx3c](https://github.com/advisories/GHSA-gg4r-jv3p-qx3c), [GHSA-6972-9mcm-vhwj](https://github.com/advisories/GHSA-6972-9mcm-vhwj), [GHSA-wr5m-5jph-8m96](https://github.com/advisories/GHSA-wr5m-5jph-8m96)). The check reads the application's Mongoose (`schema.base`), because the vulnerable code is the application's copy, not one installed by this package. Upgrade Mongoose to 7.8.13 / 8.24.7 or later.
- The development lockfile now uses Mongoose 8.24.9 (was 8.24.5). `npm audit --omit=dev` reports no vulnerabilities.

### Fixed

- `mongoose.trusted()` on an encrypted field (e.g. `{ email: mongoose.trusted({ $ne: value }) }`) is kept when the plugin rewrites the filter, so the query works with `sanitizeFilter: true`. Before, the rewritten condition lost the marker and matched nothing.

### Changed

- The `mongoose` dependency range is unchanged (`^7.0.0 || ^8.0.0`), so installs do not break.
- README: Security section. CI runs the tests on Node.js 18/20/22 with Mongoose 7.8.13 and 8.24.9, plus `npm audit`.

## 1.1.10 - 2026-10-06

### Changed

- `mongoose` dependency range is widened to `^7.0.0 || ^8.0.0` (1.1.9 was published with `^8.24.5`), so projects on any Mongoose 7 or 8 release reuse their own Mongoose instead of installing a second copy. Tested with Mongoose 7.8, 8.7 and 8.24. Mongoose 9 is supported from 2.0.0.
- README: compatibility table (1.x for Mongoose 7/8, 2.x for Mongoose 9).

No code changes since 1.1.9.

## 1.1.9 - 2026-10-06

### Fixed

- **Security:** `validAccessData: true` had no effect, so encrypted fields were always returned decrypted, even without `isShowDecrypted: true` in the async context. The option is now honoured by `find`/`findOne` (`init`), `save`, `insertMany` and `aggregate`.
- `aggregate()` no longer decrypts results when the context has no decryption rights; `hashField`/`ivField` are still removed from the output.
- Saving a document that was loaded without decryption rights no longer encrypts the stored ciphertext a second time. Only fields that were changed are re-encrypted; other fields keep their ciphertext, hash and iv.
- Clearing an encrypted field (`''`, `null`) on `save()` removes its stale search hash.
- `insertMany()` always failed with "List should not be empty" on Mongoose 7/8 because the pre hook read `next` as the documents. The hook now works with both the Mongoose 7/8 `(next, docs)` and Mongoose 9 `(docs)` signatures, accepts a single object or an empty array, and no longer hides the original error (e.g. `ValidationError`).

### Changed

- Default behaviour is unchanged: with `validAccessData: false` (default) fields are always decrypted.
- Tests now run with `npm test` (`node:test` + in-memory MongoDB, or `MONGO_URI`). The old script moved to `examples/demo.js` (`npm run demo`).
- README documents `validAccessData`, `haveDataNotEncrypt`, the need to await queries inside `userContextStore.run()`, and the known limitations of v1.x.

### Known issues (planned for 2.0.0, Mongoose 9)

- Only equality search is supported on encrypted fields; `unique` indexes on encrypted fields have no effect; the search hash is an unkeyed SHA-256.
