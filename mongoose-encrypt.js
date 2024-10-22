const crypto = require('crypto');
const omit = require('lodash/omit');
const mongoose = require('mongoose');
const hashHelper = require('./helpers/hash');

/**
 * 
 * @param {string} value - the string to encrypt
 * @param {string} salt  - the string sail
 * @param {string} algorithm - algorithm encrypt "aes-256-ctr" or "aes-256-cbc"
 * @returns {string} The string after encrypt
 */
function encryptField(value, salt, algorithm) {

    return hashHelper.encryptStr(value, salt, algorithm);
}

/**
 * 
 * @param {Object} dataDecrypt - Object have 2 value "iv" and "hash"
 * @param {string} salt  - the string sail
 * @param {string} algorithm - algorithm encrypt "aes-256-ctr" or "aes-256-cbc"
 * @returns {string} The string after decrypt
 */
function decryptField(dataDecrypt, salt, algorithm) {
    const { iv, hash } = dataDecrypt;

    if (typeof (hash) != 'string') return hash;

    if (!iv || iv.length < 32) return hash;

    const decryptData = hashHelper.decryptStr({ iv, hash }, salt, algorithm);

    return decryptData;
}

/**
 * 
 * @param {Object} options - Options to overwrite the default options
 * @returns {Object} The merge "options" with default options
 */
function defaultOptions(options) {
    if (!options?.fields?.length) {
        throw new Error(`Fields is Array and not empty`);
    }

    if (options.salt.length < 32) {
        throw new Error(`Salt length greater than 32 character`);
    }

    if (options.algorithm && !['aes-256-ctr', 'aes-256-cbc'].includes(options.algorithm)) {
        throw new Error(`Algorithm accept 'aes-256-ctr' and 'aes-256-cbc'`);
    }

    options = {
        algorithm: 'aes-256-ctr',
        hashField: 'hashField',
        ivField: 'ivField',
        hideIV: true,
        ...options
    }

    return options;
}
/**
 * 
 * ### Example:
 * 
 *      const mongoosePlugins = require('mongoose-encrypt-plugin');
 * 
 *      TestSchema.plugin(plugin.MongooseEncryptPlugin, { fields: ['email', 'phone', 'address'], salt: 'vZYt@CAkuMKB9Z#SHZF4d7puRt!MhCiK' });
 * 
 *      TestSchema.plugin(plugin.MongooseEncryptPlugin, { fields: ['email', 'phone', 'address'], salt: 'vZYt@CAkuMKB9Z#SHZF4d7puRt!MhCiK', algorithm: 'aes-256-ctr' });
 * 
 *      TestSchema.plugin(plugin.MongooseEncryptPlugin, { fields: ['email', 'phone', 'address'], salt: 'vZYt@CAkuMKB9Z#SHZF4d7puRt!MhCiK', hashField: 'encryptField' });
 * 
 *      TestSchema.plugin(plugin.MongooseEncryptPlugin, { fields: ['email', 'phone', 'address'], salt: 'vZYt@CAkuMKB9Z#SHZF4d7puRt!MhCiK', ivField: 'keyIv' });
 * 
 *      TestSchema.plugin(plugin.MongooseEncryptPlugin, { fields: ['email', 'phone', 'address'], salt: 'vZYt@CAkuMKB9Z#SHZF4d7puRt!MhCiK', hideIV: false });
 * 
 * ### Options:
 * 
 * - [fields]: array of strings - no default. List field need to encrypt
 * - [sail]: string - no default, length greater 32 character
 * - [algorithm] string - defaults to `aes-256-ctr`, accept between `aes-256-ctr` and `aes-256-cbc`
 * - [hashField] string - defaults to `hashField`
 * - [ivField] string - defaults to  `ivField`
 * - [hideIV] bool - defaults to true
 * 
 * @param {Schema} schema - The schema is Schema in mongoose
 * @param {Object} options - The options object pass to interface "IMongooseEncryptOptions"
 */
const MongooseEncryptPlugin = function (schema, options) {
    options = defaultOptions(options)

    function updateRecord(next) {
        let that = this;

        const getUpdate = that.getUpdate();
        if (getUpdate && !Array.isArray(getUpdate)) {
            const { hashField, ivField, fields, salt, algorithm } = options;

            fields.forEach(field => {
                if (getUpdate[field] && getUpdate[field] != '') {
                    const { iv, encrypted } = encryptField(getUpdate[field], salt, algorithm);

                    getUpdate[`${hashField}.${field}`] = crypto.createHash('sha256').update(getUpdate[field]).digest('base64');
                    getUpdate[`${ivField}.${field}`] = iv;
                    getUpdate[field] = encrypted;
                }
                else if (getUpdate?.['$set']?.[field] && getUpdate['$set'][field] != '') {
                    const fieldData = getUpdate['$set'][field];
                    const { iv, encrypted } = encryptField(fieldData, salt, algorithm);

                    getUpdate[`${hashField}.${field}`] = crypto.createHash('sha256').update(fieldData).digest('base64');
                    getUpdate[`${ivField}.${field}`] = iv;
                    getUpdate[field] = encrypted;
                }
            })
        }

        next()
    }

    function processFindQuery(next) {
        let that = this;
        const { hashField, ivField, fields } = options;
        const selectField = that.projection();

        if (selectField && !selectField?.hasOwnProperty(hashField)) {
            selectField[hashField] = 1
        }

        if (selectField && !selectField?.hasOwnProperty(ivField)) {
            selectField[ivField] = 1
        }

        const getQuery = that.getQuery();
        const customQuery = omit(getQuery, ["$or", "$and"]);
        let customOR = [];
        let customAND = [];

        if (getQuery && !Array.isArray(getQuery)) {


            if (getQuery['$or']) {
                const fieldOr = getQuery['$or'];
                for (let i = 0; i < fieldOr.length; i++) {
                    const standField = fieldOr[i];
                    const key = Object.keys(standField)[0];
                    const checkHashField = fields.indexOf(key);
                    if (checkHashField >= 0 && standField[key].hasOwnProperty('$eq')) {
                        customOR.push({
                            [`${hashField}.${key}`]: {
                                "$eq": crypto.createHash('sha256').update(standField[key]['$eq']).digest('base64')
                            }
                        })
                    } else {
                        customOR.push(standField);
                    }
                }

                customQuery['$or'] = customOR;
            }
            else if (getQuery['$and']) {
                const fieldAND = getQuery['$and'];
                for (let i = 0; i < fieldAND.length; i++) {
                    const standField = fieldAND[i];
                    const key = Object.keys(standField)[0];
                    const checkHashField = fields.indexOf(key);
                    if (checkHashField >= 0 && standField[key].hasOwnProperty('$eq')) {
                        customAND.push({
                            [`${hashField}.${key}`]: {
                                "$eq": crypto.createHash('sha256').update(standField[key]['$eq']).digest('base64')
                            }
                        })
                    } else {
                        customAND.push(standField);
                    }
                }

                customQuery['$and'] = customAND;
            }
            else {
                fields.forEach(field => {
                    if (customQuery[field]) {
                        customQuery[field] = crypto.createHash('sha256').update(customQuery[field]).digest('base64');
                    }
                })
            }
        }

        that.setQuery(customQuery);
        next();
    }

    function customDataAggregate(data) {
        const { hashField, ivField, salt, algorithm } = options;

        if (data.hasOwnProperty(hashField)) {
            for (const field in data[hashField]) {
                const iv = data?.[ivField]?.[field] || '';
                data[field] = decryptField({ iv, hash: data[field] }, salt, algorithm);
            }

            delete data[hashField];
            delete data[ivField];
        } else {
            for (const key in data) {
                if (typeof (data[key]) == 'object' && !Array.isArray(data[key])) {
                    const dataChild = data[key];

                    if (dataChild.hasOwnProperty(hashField)) {
                        for (const field in dataChild[hashField]) {
                            const iv = dataChild?.[ivField]?.[field] || '';
                            dataChild[field] = decryptField({ iv, hash: dataChild[field] }, salt, algorithm);
                        }

                        delete dataChild[hashField];
                        delete dataChild[ivField];
                    }
                }
            }
        }
    }

    schema.add({ [options.hashField]: mongoose.Schema.Types.Mixed, [options.ivField]: mongoose.Schema.Types.Mixed });

    schema.method('toJSON', function () {
        let that = this;
        const { hashField, ivField, hideIV } = options;
        const record = that;
        const recordObject = record.toObject();

        if (hideIV) {
            delete recordObject[hashField];
            delete recordObject[ivField];

            for (const key in recordObject) {
                if (typeof (recordObject[key]) == 'object' && !Array.isArray(recordObject[key])) {
                    const dataChild = recordObject[key];

                    if (dataChild.hasOwnProperty(hashField)) {
                        delete dataChild[hashField];
                        delete dataChild[ivField];
                    }
                }
            }
        }

        return recordObject;
    });

    schema.pre('updateOne', updateRecord);
    schema.pre('updateMany', updateRecord);
    schema.pre('findOneAndUpdate', updateRecord);
    schema.pre('find', processFindQuery);
    schema.pre('findOne', processFindQuery);

    // encrypt data (create, save) before document store in the database
    schema.pre('save', function (next) {
        let that = this;
        const dataInit = that;
        const { hashField, ivField, salt, algorithm, fields } = options;

        dataInit[hashField] = {};
        dataInit[ivField] = {};

        fields.forEach(field => {
            if (dataInit[field] && dataInit[field] != '') {
                const dataField = dataInit[field].toString();

                const { iv, encrypted } = encryptField(dataField, salt, algorithm);
                dataInit[hashField][field] = crypto.createHash('sha256').update(dataField).digest('base64');
                dataInit[ivField][field] = iv;
                dataInit[field] = encrypted;
            }
        })

        next();
    });

    schema.pre('insertMany', async function (next, docs) {
        try {
            if (Array.isArray(docs) && docs.length) {
                const { hashField, ivField, salt, algorithm, fields } = options;

                const hashFieldData = docs.map(async (data) => {
                    return await new Promise((resolve, reject) => {
                        try {
                            data[hashField] = {};
                            data[ivField] = {};

                            fields.forEach(field => {
                                if (data[field] && data[field] != '') {
                                    const { iv, encrypted } = encryptField(data[field], salt, algorithm);
                                    data[hashField][field] = crypto.createHash('sha256').update(data[field]).digest('base64');
                                    data[ivField][field] = iv;
                                    data[field] = encrypted;
                                }
                            })

                            resolve(data);
                        } catch (error) {
                            reject(error);
                        }
                    })
                });

                docs = await Promise.all(hashFieldData);
                next();
            } else {
                return next(new Error("List should not be empty"));
            }
        } catch (error) {
            console.log('error: ', error);
            return next(new Error("Something error"));
        }
    });

    schema.post('insertMany', async function (docs) {
        if (Array.isArray(docs) && docs.length) {
            const { ivField, salt, algorithm, fields } = options;

            for (let i = 0; i < docs.length; i++) {
                const doc = docs[i];

                fields.forEach(field => {
                    if (doc[field]) {
                        const iv = doc[ivField][field];
                        doc[field] = decryptField({ iv: iv, hash: doc[field] }, salt, algorithm);
                    }
                });
            }
        }
    })

    schema.post('aggregate', function (docs) {
        try {
            if (docs.length) {
                for (let data of docs) {
                    data = customDataAggregate(data);
                }
            }
        } catch (error) {
            console.log('error: ', error);
        }

    })

    // encrypt data (create, save) before document store in the database
    schema.post('save', function (doc) {
        const { ivField, salt, algorithm, fields } = options;

        fields.forEach(field => {
            if (doc[field]) {
                const iv = doc?.[ivField]?.[field] || '';
                doc[field] = decryptField({ iv, hash: doc[field].toString() }, salt, algorithm);
            }
        });
    });

    // decrypt data when document return from mongoose query
    schema.post('init', function (doc) {
        const { ivField, salt, algorithm, fields } = options;

        fields.forEach(field => {
            if (doc[field]) {
                const iv = doc?.[ivField]?.[field] || '';
                doc[field] = decryptField({ iv, hash: doc[field].toString() }, salt, algorithm);
            }
        });
    });
}

module.exports = { MongooseEncryptPlugin };