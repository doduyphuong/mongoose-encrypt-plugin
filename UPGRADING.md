# Upgrading from 1.x to 2.0

Version 2 targets **Mongoose 9** and Node.js >= 20.19. If you stay on Mongoose 7 or 8, keep using `mongoose-encrypt-plugin@1`.

## 1. Update the dependencies

```sh
npm install mongoose@^9 mongoose-encrypt-plugin@^2
```

## 2. Create two keys

v1 used a single `salt` as AES key and an unkeyed SHA-256 for search. v2 needs two different 32-byte keys:

```sh
node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"   # ENCRYPTION_KEY
node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"   # HASH_KEY
```

Store them in your secret manager or environment. Keep the old `salt` too: it is needed to read the data written by v1.

## 3. Change the plugin options

```diff
 UserSchema.plugin(MongooseEncryptPlugin, {
     fields: ['email', 'phone'],
-    salt: process.env.ENCRYPT_SALT,
-    algorithm: 'aes-256-ctr',
+    encryptionKey: process.env.ENCRYPTION_KEY,
+    hashKey: process.env.HASH_KEY,
+    legacy: { salt: process.env.ENCRYPT_SALT, algorithm: 'aes-256-ctr' },
 });
```

- Remove `unique: true` from encrypted paths and use `unique: ['email']` in the plugin options.
- Replace `getCurrentUserRole()` with `isDecryptionAllowed()`, and `userContextStore.run(ctx, () => query)` with `runWithDecryption(flag, () => query)`.
- Replace `{ new: true }` with `{ returnDocument: 'after' }` (Mongoose 9).

## 4. What works right after the upgrade

| | v1 documents | Documents written by v2 |
| --- | --- | --- |
| Read / decrypt | Yes (needs `legacy`) | Yes |
| Re-encrypted with v2 on `save()` | Yes | n/a |
| Search by an encrypted field | Yes (needs `legacy`: the old SHA-256 hash is also matched) | Yes |

The application keeps working during the migration, v1 and v2 documents side by side.

## 5. Migrate the data

Run `migrateV1` once (for example from a one-off script or a deploy job). Preview it first:

```js
const { migrateV1 } = require('mongoose-encrypt-plugin');

console.log(await migrateV1(User, { dryRun: true }));
// { scanned: 12000, migrated: 12000, failed: [], dryRun: true }

const result = await migrateV1(User, { batchSize: 500 });
if (result.failed.length) console.error(result.failed); // { _id, field, error } for values that cannot be decrypted
```

It works on the collection directly in batches, re-encrypts every v1 value with AES-256-GCM, recomputes the HMAC hash and removes `ivField`. It is safe to run again; documents changed while it runs are left for the next run.

When a run reports `migrated: 0` and no `failed` documents, remove the `legacy` option and the old salt from your configuration.

## 6. Behaviour changes to check in your code

- Operators that cannot work on ciphertext now throw `UnsupportedOperatorError`: `$regex`, RegExp, `$gt`/`$lt`, `$not` in queries; `$push`, `$inc`, `$rename`, … in updates.
- A value that cannot be decrypted throws `DecryptionError` (use `onDecryptError: 'keep'` to keep the stored value instead).
- Invalid options throw `OptionsError` when the plugin is applied, instead of failing on the first save.
