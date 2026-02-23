# Mongoose Encrypt Plugin
This plugin is build support encrypt field when you insert and update data to database.

# Install
First install [Node.js](http://nodejs.org/) and [Mongoose](https://www.npmjs.com/package/mongoose). Then:

```sh
npm install mongoose-encrypt-plugin
```

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
}
```

# Permission-Based Field Decryption

This plugin supports conditional field decryption using Node.js `async_hooks`. You can control whether encrypted fields are decrypted in the response or returned in encrypted form.

## Setup

```js
const { MongooseEncryptPlugin, userContextStore } = require('mongoose-encrypt-plugin');

// The plugin will only decrypt fields when isShowDecrypted flag is set to true in the async context
TestSchema.plugin(MongooseEncryptPlugin, {
    fields: ['email', 'phone', 'address'],
    salt: 'vZYt@CAkuMKB9Z#SHZF4d7puRt!MhCiK'
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

1. When `isShowDecrypted` is `true` in the async context, encrypted fields are decrypted and returned as plaintext
2. When `isShowDecrypted` is `false` or not set, encrypted fields remain encrypted (return hashed values)
3. Query operations (find, findById, etc.) work normally regardless of decryption setting
4. Update operations encrypt new data and respect the decryption context for the returned document
5. The `.toJSON()` method respects the permission context during serialization
6. The `.save()` post hook respects permission context when returning the saved document

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

## Example Test

See [test/index.js](./test/index.js) for complete test examples including:
- Basic CRUD operations
- Find operations with/without decryption
- Update operations with permission checks
- Insert multiple documents with permission context
