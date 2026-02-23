const mongoose = require("mongoose");
const { MongooseEncryptPlugin, userContextStore } = require('../mongoose-encrypt');

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

const SALT = 'vZYt@CAkuMKB9Z#SHZF4d7puRt!MhCiK';
TestSchema.plugin(MongooseEncryptPlugin, {
    fields: ['email', 'phone', 'address'],
    salt: SALT
});
const TestModel = mongoose.model('test', TestSchema);

const saveData = async (data) => {
    try {
        return await TestModel.create(data);
    } catch (error) {
        console.log('error: ', error);
    }

    return null;
}

const findDataWithDecryption = async (decrypt = true) => {
    return new Promise(async (resolve) => {
        userContextStore.run({ isShowDecrypted: decrypt }, async () => {
            try {
                const data = await TestModel.find().exec();
                resolve(data);
            } catch (error) {
                console.error('error: ', error);
                resolve([]);
            }
        });
    });
}

const findDataByIdWithDecryption = async (id, decrypt = true) => {
    return new Promise(async (resolve) => {
        userContextStore.run({ isShowDecrypted: decrypt }, async () => {
            try {
                const data = await TestModel.findById(id).exec();
                resolve(data);
            } catch (error) {
                console.error('error: ', error);
                resolve(null);
            }
        });
    });
}

const updateDataWithDecryption = async (id, updateData, decrypt = true) => {
    return new Promise(async (resolve) => {
        userContextStore.run({ isShowDecrypted: decrypt }, async () => {
            try {
                const data = await TestModel.findByIdAndUpdate(id, { $set: updateData }, { new: true }).exec();
                resolve(data);
            } catch (error) {
                console.error('error: ', error);
                resolve(null);
            }
        });
    });
}

async function main() {
    try {
        await mongoose.connect('mongodb://127.0.0.1:27017/test');

        console.log('\n========== TEST 1: Insert Data ==========');
        const data1 = {
            name: 'Test data 1',
            phone: '0977777777',
            email: 'test1@gmail.com',
            address: 'Ho Chi Minh City'
        }

        const data2 = {
            name: 'Test data 2',
            phone: '0966666666',
            email: 'test2@gmail.com',
            address: 'Ha Noi'
        }

        const insertedData1 = await saveData(data1);
        console.log('Data 1 inserted: ', insertedData1);

        const insertedData2 = await saveData(data2);
        console.log('Data 2 inserted: ', insertedData2);

        console.log('\n========== TEST 2: Find with Decryption (isShowDecrypted = true) ==========');
        const listDataDecrypted = await findDataWithDecryption(true);
        console.log('List data (decrypted): ');
        listDataDecrypted.forEach(doc => {
            console.log({
                name: doc.name,
                email: doc.email,
                phone: doc.phone,
                address: doc.address
            });
        });

        console.log('\n========== TEST 3: Find without Decryption (isShowDecrypted = false) ==========');
        const listDataEncrypted = await findDataWithDecryption(false);
        console.log('List data (encrypted): ');
        listDataEncrypted.forEach(doc => {
            console.log({
                name: doc.name,
                email: doc.email,   // Should be encrypted hash
                phone: doc.phone,   // Should be encrypted hash
                address: doc.address // Should be encrypted hash
            });
        });

        console.log('\n========== TEST 4: FindById with Decryption (isShowDecrypted = true) ==========');
        const findDataDecrypted = await findDataByIdWithDecryption(insertedData1._id, true);
        console.log('Find by ID (decrypted): ', {
            name: findDataDecrypted.name,
            email: findDataDecrypted.email,
            phone: findDataDecrypted.phone,
            address: findDataDecrypted.address
        });

        console.log('\n========== TEST 5: FindById without Decryption (isShowDecrypted = false) ==========');
        const findDataEncrypted = await findDataByIdWithDecryption(insertedData1._id, false);
        console.log('Find by ID (encrypted): ', {
            name: findDataEncrypted.name,
            email: findDataEncrypted.email,   // Should be encrypted
            phone: findDataEncrypted.phone,   // Should be encrypted
            address: findDataEncrypted.address // Should be encrypted
        });

        console.log('\n========== TEST 6: Update with Decryption (isShowDecrypted = true) ==========');
        const updatedDataDecrypted = await updateDataWithDecryption(
            insertedData2._id, 
            { name: 'Updated data 2', phone: '0955555555' },
            true
        );
        console.log('Update (decrypted result): ', {
            name: updatedDataDecrypted.name,
            email: updatedDataDecrypted.email,
            phone: updatedDataDecrypted.phone,
            address: updatedDataDecrypted.address
        });

        console.log('\n========== TEST 7: Update without Decryption (isShowDecrypted = false) ==========');
        const updatedDataEncrypted = await updateDataWithDecryption(
            insertedData1._id, 
            { phone: '0944444444', address: 'Da Nang' },
            false
        );
        console.log('Update (encrypted result): ', {
            name: updatedDataEncrypted.name,
            email: updatedDataEncrypted.email,   // Should be encrypted
            phone: updatedDataEncrypted.phone,   // Should be encrypted
            address: updatedDataEncrypted.address // Should be encrypted
        });

        console.log('\n========== TEST 8: Verify Updated Data (Decrypted) ==========');
        const verifyData = await findDataByIdWithDecryption(insertedData1._id, true);
        console.log('Verify update - phone should be 0944444444: ', verifyData.phone);
        console.log('Verify update - address should be Da Nang: ', verifyData.address);

        console.log('\n========== TEST 9: toJSON() with Decryption Context ==========');
        const dataForJSON = await findDataByIdWithDecryption(insertedData2._id, true);
        console.log('toJSON() with decryption: ', dataForJSON.toJSON());

        console.log('\n========== TEST 10: toJSON() without Decryption Context ==========');
        const dataForJSONEncrypted = await findDataByIdWithDecryption(insertedData2._id, false);
        console.log('toJSON() without decryption: ', dataForJSONEncrypted.toJSON());

        await mongoose.disconnect();
        console.log('\n========== All tests completed ==========');

    } catch (error) {
        console.error(error, 'error');
    }
}

main();