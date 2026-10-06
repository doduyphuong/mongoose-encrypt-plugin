/**
 * Bugs from the review that v2 has not fixed yet.
 * Their tests run, but a failure is reported as TODO so CI stays green while the fix is in progress.
 * `npm run test:strict` (MEP_STRICT=1) turns them into normal tests to see which ones are still red.
 * Remove the `pending(...)` option from a test once its fix lands.
 * @param {string} phase - the plan phase that fixes the bug, e.g. 'GD 2'
 */
function pending(phase) {
    return process.env.MEP_STRICT ? {} : { todo: `v2 ${phase}` };
}

module.exports = { pending };
