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
const mongoosePlugins = require('mongoose-encrypt-plugin');.

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
# Option config

These are the available config for plugin.

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
