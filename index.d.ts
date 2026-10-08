import type { AsyncLocalStorage } from 'node:async_hooks';
import type { Model, Schema } from 'mongoose';

/** A 32-byte key: a Buffer, a 64-char hex string, a base64 string or a 32-character string. */
export type EncryptionKey = Buffer | string;

export interface LegacyOptions {
    /** The `salt` option used with plugin v1 (its AES key). */
    salt: EncryptionKey;
    /** The `algorithm` option used with plugin v1. Defaults to `aes-256-ctr`. */
    algorithm?: 'aes-256-ctr' | 'aes-256-cbc';
}

export interface MongooseEncryptOptions {
    /** Top-level String fields to encrypt. */
    fields: string[];
    /** 32-byte AES-256-GCM key. */
    encryptionKey: EncryptionKey;
    /** 32-byte HMAC key for the search hash. Must be different from `encryptionKey`. */
    hashKey: EncryptionKey;
    /** Encrypted fields that must be unique (a unique index on their hash). Defaults to `[]`. */
    unique?: string[];
    /** What to do when a stored value cannot be decrypted. Defaults to `'throw'`. */
    onDecryptError?: 'throw' | 'keep';
    /** Read (and re-encrypt on save) data written by plugin v1. */
    legacy?: LegacyOptions;
    /** Field that stores the search hashes. Defaults to `'hashField'`. */
    hashField?: string;
    /** Field that stores the iv of values written by v1. Defaults to `'ivField'`. */
    ivField?: string;
    /** Hide `hashField` / `ivField` in `toJSON()`. Defaults to `true`. */
    hideIV?: boolean;
    /** Queries also match values still stored in plaintext. Defaults to `false`. */
    haveDataNotEncrypt?: boolean;
    /** Decrypt only inside `runWithDecryption(true, fn)`. Defaults to `false` (always decrypt). */
    validAccessData?: boolean;
}

export interface DecryptionContext {
    isShowDecrypted: boolean;
}

export interface MigrateOptions {
    /** Documents read and written per batch. Defaults to 500. */
    batchSize?: number;
    /** Count and check only, write nothing. Defaults to false. */
    dryRun?: boolean;
    /** Also encrypt values still stored in plaintext. Defaults to false. */
    includePlaintext?: boolean;
    /** Called after each batch. */
    onProgress?: (stats: MigrateResult) => void;
}

export interface MigrateResult {
    scanned: number;
    migrated: number;
    failed: Array<{ _id: unknown; field: string; error: string }>;
    dryRun: boolean;
}

/** Statics added to every model whose schema uses the plugin. */
export interface MongooseEncryptStatics {
    migrateEncryption(options?: MigrateOptions): Promise<MigrateResult>;
}

/** Re-encrypt, in batches, the documents still holding values written by plugin v1 (needs the `legacy` option). */
export declare function migrateV1(model: Model<any>, options?: MigrateOptions): Promise<MigrateResult>;

export declare function MongooseEncryptPlugin(schema: Schema<any, any, any, any>, options: MongooseEncryptOptions): void;

/** Async context read by the plugin when `validAccessData` is true. */
export declare const userContextStore: AsyncLocalStorage<DecryptionContext>;

/** Run `fn` with the given decryption rights; the returned query / promise is awaited inside the context. */
export declare function runWithDecryption<T>(isShowDecrypted: boolean, fn: () => T | PromiseLike<T>): Promise<Awaited<T>>;

/** Whether the current async context allows decrypted values. */
export declare function isDecryptionAllowed(): boolean;

/** @deprecated since 2.0.0, use `isDecryptionAllowed()`. */
export declare function getCurrentUserRole(): boolean;

export declare class MongooseEncryptError extends Error {}

/** Invalid plugin options, thrown by `schema.plugin()`. */
export declare class OptionsError extends MongooseEncryptError {}

/** A stored value could not be decrypted (tampered, corrupted or another key). */
export declare class DecryptionError extends MongooseEncryptError {
    constructor(field: string, cause?: unknown);
    readonly field: string;
    readonly cause: unknown;
}

/** A query or update uses an operator that cannot work on an encrypted field. */
export declare class UnsupportedOperatorError extends MongooseEncryptError {
    constructor(field: string, operator: string, hint?: string);
    readonly field: string;
    readonly operator: string;
}
