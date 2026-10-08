# Changelog

## 2.0.0-beta.0 - Unreleased

Version 2 targets **Mongoose 9** (Node.js >= 20.19). Mongoose 7/8 users stay on 1.x. See [UPGRADING.md](./UPGRADING.md).

### Breaking changes

- `mongoose` is a peer dependency (`^9.0.0`); Node.js >= 20.19 is required.
- Options `salt` and `algorithm` are replaced by `encryptionKey` and `hashKey` (two different 32-byte keys). Passing the old options throws an `OptionsError` that explains the change.
- New values are encrypted with AES-256-GCM and stored as `v2:<iv>:<tag>:<ciphertext>`; `ivField` is only used by data written by v1.
- The search hash is HMAC-SHA256 with `hashKey` instead of an unkeyed SHA-256. With the `legacy` option, v1 documents stay searchable until they are migrated with `migrateV1` (see UPGRADING.md).
- `unique: true` on an encrypted path throws; use the plugin option `unique: ['field']`.
- Unsupported query operators on encrypted fields (`$regex`, RegExp, `$gt`, …) and update operators (`$push`, `$inc`, `$rename`, …) throw `UnsupportedOperatorError` instead of failing silently or crashing.
- Invalid options throw `OptionsError` when the plugin is applied; a value that cannot be decrypted throws `DecryptionError` (or use `onDecryptError: 'keep'`).

### Added

- Options `unique`, `onDecryptError` and `legacy: { salt, algorithm }`: read and search v1 data, and re-encrypt it with v2 on save.
- `migrateV1(Model, { batchSize, dryRun, includePlaintext, onProgress })` (also `Model.migrateEncryption()`): re-encrypt a whole collection written by v1, in batches, safe to run again.
- `runWithDecryption(isShowDecrypted, fn)`, `isDecryptionAllowed()`; error classes `MongooseEncryptError`, `OptionsError`, `DecryptionError`, `UnsupportedOperatorError`.
- TypeScript declarations (`index.d.ts`).
- Search, update and delete by encrypted fields in `updateOne`, `updateMany`, `findOneAndUpdate`, `replaceOne`, `findOneAndReplace`, `deleteOne`, `deleteMany`, `findOneAndDelete`, `distinct` and the leading `$match` stages of `aggregate`.
- `$in`, `$nin`, `$exists` and `$nor` on encrypted fields; values are compared by their string form.
- `$setOnInsert` is encrypted; `$unset` of an encrypted field removes its hash; `replaceOne` / `findOneAndReplace` encrypt the replacement.

### Fixed

- `$and` with several encrypted fields was turned into an `$or`; with `haveDataNotEncrypt`, conditions were mixed into the user `$or`.
- Only the first key of each `$or` / `$and` branch was rewritten; nested conditions were ignored.
- An exclusion projection made MongoDB reject the query.
- Clearing an encrypted field with an update left its old hash, so the old value could still be found.
- `toJSON()` ignored the schema `toJSON` options (virtuals, transform).
- Update pipelines (`updatePipeline: true`) could write plaintext.
- A document loaded from the database had all its encrypted fields marked as modified.

### Removed

- `lodash` dependency, `helpers/hash.js`, the `count` query hook (removed from Mongoose).
- `getCurrentUserRole()` is deprecated in favour of `isDecryptionAllowed()`.

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
