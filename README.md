# Mongoose Encrypt Plugin

Encrypt fields of a Mongoose schema with **AES-256-GCM** before they reach MongoDB, and keep them searchable by equality through a keyed hash (HMAC-SHA256 blind index).

- Authenticated encryption: tampered or corrupted values are detected, never returned as garbage
- Search, update and delete by an encrypted field (`find({ email })`, `updateOne({ email }, …)`, `$in`, `$ne`, …)
- Unique encrypted fields (`unique: ['email']`)
- Optional permission-based decryption per request (`runWithDecryption`)
- Reads, searches and migrates data written by plugin v1 (`migrateV1`)

## Compatibility

| Plugin version | Mongoose | Node.js |
| --- | --- | --- |
| 2.x | 9.x | >= 20.19 |
| 1.x | 7.x, 8.x | as required by your Mongoose version |

Upgrading from 1.x? Read [UPGRADING.md](./UPGRADING.md).

## Install

```sh
npm install mongoose-encrypt-plugin mongoose
```

## Quick start

Generate two different 32-byte keys once and keep them in your secret manager / environment, never in the code:

```sh
node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"
```

## Compatibility

| Plugin version | Mongoose | Node.js |
| --- | --- | --- |
| 1.x | 7.x, 8.x | as required by your Mongoose version |
| 2.x (planned) | 9.x | >= 20.19 |

# Quick Guide
#### Basic Usage
```js
const mongoose = require('mongoose');
const { MongooseEncryptPlugin } = require('mongoose-encrypt-plugin');

const UserSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true }, // no `unique: true` here, see the `unique` option
    phone: { type: String, default: '' },
});

UserSchema.plugin(MongooseEncryptPlugin, {
    fields: ['email', 'phone'],
    encryptionKey: process.env.ENCRYPTION_KEY,
    hashKey: process.env.HASH_KEY,
    unique: ['email'],
});

const User = mongoose.model('User', UserSchema);

await User.create({ name: 'An', email: 'an@example.com', phone: '0901234567' });
const user = await User.findOne({ email: 'an@example.com' }); // search by the plaintext value
console.log(user.email); // 'an@example.com'
```

In MongoDB the document looks like this:

```js
{
  name: 'An',
  email: 'v2:<iv>:<auth tag>:<ciphertext>',
  phone: 'v2:…',
  hashField: { email: '<HMAC-SHA256>', phone: '<HMAC-SHA256>' }
}
```

## Options

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `fields` | `string[]` | required | Top-level `String` fields to encrypt |
| `encryptionKey` | `Buffer \| string` | required | 32-byte AES-256-GCM key (Buffer, 64-char hex, base64 or 32-character string) |
| `hashKey` | `Buffer \| string` | required | 32-byte HMAC key for the search hash, different from `encryptionKey` |
| `unique` | `string[]` | `[]` | Encrypted fields that must be unique (unique sparse index on the hash) |
| `onDecryptError` | `'throw' \| 'keep'` | `'throw'` | `'throw'` rejects the query with `DecryptionError`; `'keep'` returns the stored value |
| `validAccessData` | `boolean` | `false` | Decrypt only inside `runWithDecryption(true, …)` |
| `haveDataNotEncrypt` | `boolean` | `false` | Queries also match values still stored in plaintext (collections being migrated) |
| `legacy` | `{ salt, algorithm? }` | none | Key (`salt`) and algorithm of plugin v1, to read data written by v1 |
| `hashField` | `string` | `'hashField'` | Field that stores the search hashes |
| `ivField` | `string` | `'ivField'` | Field that stores the iv of values written by v1 |
| `hideIV` | `boolean` | `true` | Hide `hashField` / `ivField` in `toJSON()` |

Invalid options throw an `OptionsError` when the plugin is applied, with a message that says what to fix.

## Queries

Encrypted fields can be used in the filters of `find`, `findOne`, `countDocuments`, `distinct`, `updateOne`, `updateMany`, `findOneAndUpdate`, `replaceOne`, `findOneAndReplace`, `deleteOne`, `deleteMany`, `findOneAndDelete`, of every `bulkWrite` operation, and in the leading `$match` stages of `aggregate`. Conditions can be nested in `$and`, `$or` and `$nor`.

| Operator on an encrypted field | Supported |
| --- | --- |
| Plain value, `$eq`, `$ne`, `$in`, `$nin` | Yes (values are compared by their string form) |
| `$exists` | Yes: `true` matches documents that store a non-empty value |
| `$regex`, RegExp, `$gt`, `$lt`, `$not`, `$text`, … | No: throws `UnsupportedOperatorError` |

The hash only allows exact matches: there is no partial, case-insensitive or range search on encrypted fields.

## Updates

- `save()`, `create()`, `insertMany()`, `replaceOne()`, `findOneAndReplace()`, `bulkWrite()` and `bulkSave()` encrypt every write.
- A plain value, `$set` and `$setOnInsert` are encrypted and their hash is updated.
- `$unset` (or setting `''` / `null`) also removes the hash, so the old value can no longer be found.
- `$push`, `$inc`, `$rename`, paths inside an encrypted field (`'email.x'`) throw `UnsupportedOperatorError`.
- Update pipelines (`updatePipeline: true`) that write an encrypted field, or use `$replaceRoot` / `$replaceWith`, throw `UnsupportedOperatorError` before anything is sent to MongoDB.

## Permission-based decryption

With `validAccessData: true`, values are decrypted only for code running inside `runWithDecryption(true, fn)`. Elsewhere documents keep the stored ciphertext, and search by encrypted fields still works.

```js
const { runWithDecryption } = require('mongoose-encrypt-plugin');

const user = await runWithDecryption(true, () => User.findById(id));   // decrypted
const masked = await runWithDecryption(false, () => User.findById(id)); // ciphertext
```

In Express, set the rights once per request:

```js
const { userContextStore } = require('mongoose-encrypt-plugin');

app.use((req, res, next) => {
    userContextStore.run({ isShowDecrypted: req.user?.canViewSensitiveData === true }, next);
});
```

> Mongoose queries are lazy: `userContextStore.run(ctx, () => User.findById(id))` returns the query unexecuted, and awaiting it later runs it outside the context. `runWithDecryption` awaits it inside the context for you.

Saving a document that was loaded without decryption rights is safe: unchanged encrypted fields are kept as they are.

## Errors

| Error | When |
| --- | --- |
| `OptionsError` | Invalid plugin options (thrown by `schema.plugin()`) |
| `DecryptionError` | A stored value was tampered with, is corrupted or was encrypted with another key (`err.field`) |
| `UnsupportedOperatorError` | A query or update operator cannot work on an encrypted field (`err.field`, `err.operator`) |

All of them extend `MongooseEncryptError` and are exported by the package.

## Limitations

- Only top-level `String` paths can be encrypted (no nested paths, arrays, numbers, dates or UUIDs); other paths throw an `OptionsError`. Apply the plugin after the fields are defined.
- `aggregate()` decrypts the encrypted fields under their own name only; a field renamed in a `$project` / `$group` keeps its ciphertext.
- `toJSON()` hides `hashField` / `ivField`; `toObject()` keeps them (Mongoose uses it internally).
- The search hash is deterministic: two documents with the same value have the same hash, so someone who can read the database can see which documents share a value (but not the value itself).
- Keep both keys secret. Losing `encryptionKey` makes the data unreadable; changing `hashKey` requires recomputing every hash.
- `distinct()` on an encrypted field returns ciphertexts.

## Migrating data written by v1

Add the `legacy` option with the old `salt`. v1 documents are then read, searched by encrypted fields, and re-encrypted with v2 whenever they are saved. To migrate the whole collection at once:

```js
const { migrateV1 } = require('mongoose-encrypt-plugin');

const preview = await migrateV1(User, { dryRun: true });   // { scanned, migrated, failed, dryRun }
const result = await migrateV1(User, {
    batchSize: 500,
    onProgress: ({ scanned, migrated }) => console.log(scanned, migrated),
});
```

- Works on the collection directly (no middleware, no decryption rights needed), in batches ordered by `_id`.
- Safe to run again: documents already migrated are skipped; a document changed during the run is left for the next run.
- A value that cannot be decrypted is reported in `failed` and its document is left untouched.
- `includePlaintext: true` also encrypts values still stored in plaintext (`haveDataNotEncrypt`).
- When `migrateV1` reports `migrated: 0` and no `failed`, remove the `legacy` option.

See [UPGRADING.md](./UPGRADING.md) for the full upgrade path.

## TypeScript

Types are included (`index.d.ts`): `MongooseEncryptOptions`, `runWithDecryption`, the error classes, …

## Development

```sh
npm test            # node:test + in-memory MongoDB (or set MONGO_URI)
npm run test:types  # tsd
npm run demo        # examples/demo.js, needs a local MongoDB
```
