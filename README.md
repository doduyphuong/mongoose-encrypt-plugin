# Mongoose Encrypt Plugin
This plugin is build support encrypt field when you insert and update data to database.

# Install
First install [Node.js](http://nodejs.org/) and [Mongoose](https://www.npmjs.com/package/mongoose). Then:

```sh
npm install mongoose-encrypt-plugin
```

## Compatibility

| Plugin version | Mongoose | Node.js |
| --- | --- | --- |
| 1.x | 7.x, 8.x | as required by your Mongoose version |
| 2.x (planned) | 9.x | >= 20.19 |

# Quick Guide
#### Basic Usage
```js
const mongoose = require("mongoose");
const plugin = require('mongoose-encrypt-plugin');

const TestSchema = new mongoose.Schema(
    {
        name: {
            type: String,
            required: true,
        },
        phone: {
            type: String,
            required: false,
            default: ''
        },
        email: {
            type: String,
            required: true,
            unique: true,
        },
        address: {
            type: String,
            required: false,
            default: ''
        }
    },
    {
        timestamps: true,
    }
);

TestSchema.plugin(plugin.MongooseEncryptPlugin, { fields: ['email', 'phone', 'address'], salt: 'vZYt@CAkuMKB9Z#SHZF4d7puRt!MhCiK' });

```

# Option Config

These are the available config options for the plugin.

```js
{
  // `fields` is array list field need to encrypt
  fields: [],

  // `salt` is secretKey need to encrypt data. It need length greater 32 character.
  salt: 'vZYt@CAkuMKB9Z#SHZF4d7puRt!MhCiK',

  // `algorithm` accept between `aes-256-ctr` and `aes-256-cbc`
  algorithm?: 'aes-256-ctr' || 'aes-256-cbc'

  // `hashField` is field name schema store data encrypt with `sha256` support for search equal value from mongoose query
  // You can change it if you want.
  hashField?: 'hashField'

  // `ivField` is field name schema store iv key when data be encrypt, support for descrypt document when document return from mongoose query
  // You can change it if you want.
  ivField?: 'ivField'

  // `hideIV` is field verify when document return ignore field `hashField` and `ivField`
  // Default value is true
  hideIV?: true

  // `haveDataNotEncrypt` set to true when the collection still has old documents stored in plaintext.
  // Queries on encrypted fields will then match both the encrypted and the plaintext value.
  // Default value is false
  haveDataNotEncrypt?: false

  // `validAccessData` enables permission-based decryption (see below).
  // false (default): encrypted fields are always decrypted.
  // true: encrypted fields are decrypted only when `isShowDecrypted` is true in the async context.
  validAccessData?: false
}
```

# Permission-Based Field Decryption

This plugin supports conditional field decryption using Node.js `async_hooks`. You can control whether encrypted fields are decrypted in the response or returned in encrypted form.

> **Requires `validAccessData: true`.** With the default `validAccessData: false`, encrypted fields are always decrypted and `isShowDecrypted` is ignored (versions before 1.1.9 ignored it in every case).

## Setup

```js
const { MongooseEncryptPlugin, userContextStore } = require('mongoose-encrypt-plugin');

// The plugin will only decrypt fields when isShowDecrypted flag is set to true in the async context
TestSchema.plugin(MongooseEncryptPlugin, {
    fields: ['email', 'phone', 'address'],
    salt: 'vZYt@CAkuMKB9Z#SHZF4d7puRt!MhCiK',
    validAccessData: true
});

const TestModel = mongoose.model('test', TestSchema);
```

## How to Control Decryption

### Using userContextStore directly

```js
const { userContextStore } = require('mongoose-encrypt-plugin');

// Decrypt fields - show plaintext
await new Promise((resolve) => {
    userContextStore.run({ isShowDecrypted: true }, async () => {
        const user = await TestModel.findById(userId);
        console.log(user.toJSON()); 
        // Output: { name: 'John', email: 'john@example.com', phone: '555-1234', address: '123 Main St' }
        resolve();
    });
});

// Don't decrypt fields - keep encrypted
await new Promise((resolve) => {
    userContextStore.run({ isShowDecrypted: false }, async () => {
        const user = await TestModel.findById(userId);
        console.log(user.toJSON()); 
        // Output: { name: 'John', email: 'a3x5k2...', phone: 'h9j2l1...', address: 'q8w2p5...' }
        resolve();
    });
});
```

### Inside Express Middleware

```js
const { userContextStore } = require('mongoose-encrypt-plugin');

// Create middleware to set decrypt flag based on user role/permission
app.use((req, res, next) => {
    // Decide based on user's role or permission
    const isShowDecrypted = req.user?.canViewSensitiveData === true;
    
    userContextStore.run({ isShowDecrypted }, () => {
        next();
    });
});

// Now all queries within this request will respect the isShowDecrypted flag
app.get('/api/users/:id', async (req, res) => {
    const user = await User.findById(req.params.id);
    res.json(user.toJSON());
});
```

## How It Works

With `validAccessData: true`:

1. When `isShowDecrypted` is `true` in the async context, encrypted fields are decrypted and returned as plaintext
2. When `isShowDecrypted` is `false` or not set, encrypted fields remain encrypted (the stored ciphertext is returned)
3. Query operations (find, findById, etc.) work normally regardless of decryption setting, including search by an encrypted field
4. Update operations encrypt new data and respect the decryption context for the returned document
5. `.toJSON()` returns the values as they were loaded (decrypted or encrypted)
6. The `.save()` post hook respects permission context when returning the saved document
7. `aggregate()` results follow the same rule
8. Saving a document that was loaded without decryption rights is safe: unchanged encrypted fields are kept as they are, only fields you set are encrypted again

> **Await the query inside `run()`.** Mongoose queries are lazy. `userContextStore.run(ctx, () => Model.findById(id))` returns the query unexecuted, so it runs *outside* the context when you await it later. Always write `userContextStore.run(ctx, async () => await Model.findById(id))`, or run the whole request handler inside the context as in the Express example.

## Query Examples

### Find with Decryption Enabled

```js
// User can see plaintext
await userContextStore.run({ isShowDecrypted: true }, async () => {
    const users = await TestModel.find({ email: 'john@example.com' });
    console.log(users[0].email); // 'john@example.com' (decrypted)
});
```

### Find with Decryption Disabled

```js
// User cannot see plaintext
await userContextStore.run({ isShowDecrypted: false }, async () => {
    const users = await TestModel.find({ email: 'john@example.com' });
    console.log(users[0].email); // 'a3x5k2...' (encrypted hash)
});
```

### Update with Decryption

```js
// Update and get back decrypted data
await userContextStore.run({ isShowDecrypted: true }, async () => {
    const updated = await TestModel.findByIdAndUpdate(
        userId, 
        { $set: { phone: '555-9999' } },
        { new: true }
    );
    console.log(updated.phone); // '555-9999' (decrypted)
});
```

## Example

See [examples/demo.js](./examples/demo.js) (`npm run demo`, needs a local MongoDB) for a walkthrough of:
- Basic CRUD operations
- Find operations with/without decryption
- Update operations with permission checks

Run the automated tests with `npm test` (uses an in-memory MongoDB, or `MONGO_URI` when set).

# Known limitations (v1.x)

These are addressed in v2 (Mongoose 9):

- Only equality search (`value`, `$eq`, `$ne`) is supported on encrypted fields; `$regex`, `$in`, `$exists`, ranges are not
- `unique: true` on an encrypted field has no effect, because the ciphertext is different every time
- The search hash is an unkeyed SHA-256 of the value; low-entropy values (phone numbers, short codes) can be guessed by anyone who can read the database
