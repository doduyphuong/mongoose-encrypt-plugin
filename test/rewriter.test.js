// Table-driven unit tests of the filter rewriter (no database).
const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { createFilterRewriter } = require('../src/query');

const hashValues = (v) => [`H(${v})`];
const legacyValues = (v) => [`H(${v})`, `S(${v})`];
const build = (haveDataNotEncrypt = false, values = hashValues) =>
    createFilterRewriter({ fields: ['email', 'phone'], hashField: 'h', haveDataNotEncrypt, hashValues: values });

const cases = [
    ['plain value', { email: 'a' }, { 'h.email': 'H(a)' }],
    ['other fields are kept', { email: 'a', name: 'n' }, { name: 'n', 'h.email': 'H(a)' }],
    ['$eq', { email: { $eq: 'a' } }, { 'h.email': { $eq: 'H(a)' } }],
    ['$ne', { email: { $ne: 'a' } }, { 'h.email': { $ne: 'H(a)' } }],
    ['$in', { email: { $in: ['a', 'b'] } }, { 'h.email': { $in: ['H(a)', 'H(b)'] } }],
    ['$nin', { email: { $nin: ['a'] } }, { 'h.email': { $nin: ['H(a)'] } }],
    ['$exists', { email: { $exists: 1 } }, { 'h.email': { $exists: true } }],
    ['number is hashed as a string', { phone: 111 }, { 'h.phone': 'H(111)' }],
    ['null keeps null', { email: null }, { 'h.email': null }],
    ['two operators become two clauses', { email: { $ne: 'a', $exists: true } },
        { $and: [{ 'h.email': { $ne: 'H(a)' } }, { 'h.email': { $exists: true } }] }],
    ['$and keeps AND semantics', { $and: [{ email: 'a' }, { phone: '1' }] },
        { $and: [{ 'h.email': 'H(a)' }, { 'h.phone': 'H(1)' }] }],
    ['every key of an $or branch', { $or: [{ name: 'n', email: 'a' }] },
        { $or: [{ name: 'n', 'h.email': 'H(a)' }] }],
    ['$nor', { $nor: [{ email: 'a' }] }, { $nor: [{ 'h.email': 'H(a)' }] }],
    ['nested $and[$or]', { $and: [{ $or: [{ email: 'a' }, { phone: '1' }] }] },
        { $and: [{ $or: [{ 'h.email': 'H(a)' }, { 'h.phone': 'H(1)' }] }] }],
    ['two encrypted fields at top level', { email: 'a', phone: '1' },
        { $and: [{ 'h.email': 'H(a)' }, { 'h.phone': 'H(1)' }] }],
];

const haveDataCases = [
    ['plain value matches either form', { email: 'a' }, { $and: [{ $or: [{ email: 'a' }, { 'h.email': 'H(a)' }] }] }],
    ['$ne excludes both forms', { email: { $ne: 'a' } }, { $and: [{ $and: [{ email: { $ne: 'a' } }, { 'h.email': { $ne: 'H(a)' } }] }] }],
    ['$exists on the field itself', { email: { $exists: true } }, { email: { $exists: true } }],
    ['the user $or is kept intact', { email: 'a', $or: [{ name: 'x' }] },
        { $or: [{ name: 'x' }], $and: [{ $or: [{ email: 'a' }, { 'h.email': 'H(a)' }] }] }],
];

const legacyCases = [
    ['plain value matches v2 and v1 hashes', { email: 'a' }, { 'h.email': { $in: ['H(a)', 'S(a)'] } }],
    ['$ne excludes both hashes', { email: { $ne: 'a' } }, { 'h.email': { $nin: ['H(a)', 'S(a)'] } }],
    ['$in includes both hashes', { email: { $in: ['a'] } }, { 'h.email': { $in: ['H(a)', 'S(a)'] } }],
];

const unsupported = [
    ['$regex', { email: { $regex: 'a' } }],
    ['RegExp', { email: /a/ }],
    ['RegExp in $in', { email: { $in: [/a/] } }],
    ['$gt', { phone: { $gt: '1' } }],
    ['$not', { email: { $not: { $eq: 'a' } } }],
    ['$regex inside $or', { $or: [{ email: { $regex: 'a' } }] }],
    ['$in without an array', { email: { $in: 'a' } }],
];

describe('createFilterRewriter', () => {
    for (const [name, input, expected] of cases) {
        it(name, () => assert.deepEqual(build()(input), expected));
    }

    for (const [name, input, expected] of haveDataCases) {
        it(`haveDataNotEncrypt: ${name}`, () => assert.deepEqual(build(true)(input), expected));
    }

    for (const [name, input, expected] of legacyCases) {
        it(`legacy: ${name}`, () => assert.deepEqual(build(false, legacyValues)(input), expected));
    }

    for (const [name, input] of unsupported) {
        it(`throws UnsupportedOperatorError: ${name}`, () => {
            assert.throws(() => build()(input), (err) => err.name === 'UnsupportedOperatorError');
        });
    }

    it('does not modify its input', () => {
        const input = { email: 'a', $or: [{ phone: '1' }] };
        const copy = structuredClone(input);
        build()(input);
        assert.deepEqual(input, copy);
    });
});
