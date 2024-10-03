const mongoose = require("mongoose");
const plugin = require('../mongoose-encrypt');

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
TestSchema.plugin(plugin.MongooseEncryptPlugin, {
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

const getDataTest1 = async () => {
    try {
        return await TestModel.find().exec();
    } catch (error) {
        console.error('error: ', error);
    }

    return [];
}

const getDataTest2 = async () => {
    try {
        return await TestModel.find().select('name phone email address').exec();
    } catch (error) {
        console.error('error: ', error);
    }

    return [];
}

const updateData = async (id, data) => {
    try {
        return await TestModel.findByIdAndUpdate(id, { $set: data }).exec();
    } catch (error) {
        console.error('error: ', error);
    }

    return [];
}

async function main() {
    try {
        await mongoose.connect('mongodb://127.0.0.1:27017/test');

        const data1 = {
            name: 'Test data 1',
            phone: '0977777777',
            email: 'test@gmail.com',
            address: 'Ho Chi Minh City'
        }

        const data2 = {
            name: 'Test data 2',
            phone: '0966666666',
            email: 'test@gmail.com',
            address: 'Ho Chi Minh City'
        }

        const initData1 = await saveData(data1);
        console.log('Data insert: ', initData1);

        const initData2 = await saveData(data2);
        console.log('Data insert: ', initData2);

        const listDataTest1 = await getDataTest1();
        console.log('List Data Test 1: ', listDataTest1);

        const listDataTest2 = await getDataTest2();
        console.log('List Data Test 1: ', listDataTest2);

        const uData = await updateData(initData2._id, { name: 'Test data update', phone: '0955555555' });
        console.log('Update Data: ', uData);

    } catch (error) {
        console.error(error, 'error');
    }
}

main();