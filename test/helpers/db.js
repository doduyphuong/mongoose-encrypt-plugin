const mongoose = require('mongoose');

let server = null;

/**
 * Connect mongoose to a test database.
 * Uses MONGO_URI when provided, otherwise starts an in-memory MongoDB.
 */
async function connect() {
    let uri = process.env.MONGO_URI;

    if (!uri) {
        const { MongoMemoryServer } = require('mongodb-memory-server-core');
        server = await MongoMemoryServer.create();
        uri = server.getUri();
    }

    await mongoose.connect(uri, { dbName: `mep_test_${process.pid}_${Date.now()}` });
}

async function disconnect() {
    if (mongoose.connection.readyState === 1) {
        await mongoose.connection.dropDatabase();
        await mongoose.disconnect();
    }

    if (server) {
        await server.stop();
        server = null;
    }
}

module.exports = { connect, disconnect };
