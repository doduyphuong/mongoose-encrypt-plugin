import { expectError, expectType } from 'tsd';
import { Schema, model } from 'mongoose';
import {
    MongooseEncryptPlugin,
    runWithDecryption,
    isDecryptionAllowed,
    userContextStore,
    DecryptionError,
    UnsupportedOperatorError,
    migrateV1,
    type MigrateResult,
    type MongooseEncryptOptions,
} from '..';

const schema = new Schema({ name: String, email: String });

schema.plugin(MongooseEncryptPlugin, {
    fields: ['email'],
    encryptionKey: Buffer.alloc(32, 1),
    hashKey: 'b'.repeat(32),
    unique: ['email'],
    onDecryptError: 'keep',
    legacy: { salt: 'c'.repeat(32), algorithm: 'aes-256-cbc' },
});

expectError<MongooseEncryptOptions>({ fields: ['email'], encryptionKey: 'a'.repeat(32) });
expectError<MongooseEncryptOptions>({ fields: ['email'], encryptionKey: 'a', hashKey: 'b', onDecryptError: 'ignore' });

const User = model('User', schema);

expectType<Promise<MigrateResult>>(migrateV1(User, { batchSize: 100, dryRun: true, onProgress: (s) => s.scanned }));
expectError(migrateV1(User, { batchSize: '100' }));

expectType<Promise<boolean>>(runWithDecryption(true, () => isDecryptionAllowed()));
expectType<Promise<number>>(runWithDecryption(false, async () => 1));
runWithDecryption(true, () => User.findOne({ email: 'a@example.com' })).then((doc) => doc?.email);

expectType<boolean | undefined>(userContextStore.getStore()?.isShowDecrypted);

const decryptionError = new DecryptionError('email');
expectType<string>(decryptionError.field);
expectType<string>(new UnsupportedOperatorError('email', '$regex').operator);
