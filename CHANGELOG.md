# Changelog

## 1.1.9 - 2026-10-06

### Fixed

- **Security:** `validAccessData: true` had no effect, so encrypted fields were always returned decrypted, even without `isShowDecrypted: true` in the async context. The option is now honoured by `find`/`findOne` (`init`), `save`, `insertMany` and `aggregate`.
- `aggregate()` no longer decrypts results when the context has no decryption rights; `hashField`/`ivField` are still removed from the output.
- Saving a document that was loaded without decryption rights no longer encrypts the stored ciphertext a second time. Only fields that were changed are re-encrypted; other fields keep their ciphertext, hash and iv.
- Clearing an encrypted field (`''`, `null`) on `save()` removes its stale search hash.
- `insertMany()` always failed with "List should not be empty" on Mongoose 7/8 because the pre hook read `next` as the documents. The hook now works with both the Mongoose 7/8 `(next, docs)` and Mongoose 9 `(docs)` signatures, accepts a single object or an empty array, and no longer hides the original error (e.g. `ValidationError`).

### Changed

- `mongoose` dependency range is `^7.0.0 || ^8.0.0`, so projects on any Mongoose 7 or 8 release reuse their own Mongoose instead of installing a second copy. Tested with Mongoose 7.8, 8.7 and 8.24. Mongoose 9 is supported from 2.0.0.
- Default behaviour is unchanged: with `validAccessData: false` (default) fields are always decrypted.
- Tests now run with `npm test` (`node:test` + in-memory MongoDB, or `MONGO_URI`). The old script moved to `examples/demo.js` (`npm run demo`).
- README documents `validAccessData`, `haveDataNotEncrypt`, the need to await queries inside `userContextStore.run()`, and the known limitations of v1.x.

### Known issues (planned for 2.0.0, Mongoose 9)

- Only equality search is supported on encrypted fields; `unique` indexes on encrypted fields have no effect; the search hash is an unkeyed SHA-256.
