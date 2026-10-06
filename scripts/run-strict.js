// Cross-platform `MEP_STRICT=1 node --test`: pending v2 tests fail the run instead of being TODO.
const { spawnSync } = require('node:child_process');

const result = spawnSync(process.execPath, ['--test', ...process.argv.slice(2)], {
    stdio: 'inherit',
    env: { ...process.env, MEP_STRICT: '1' },
});

process.exit(result.status ?? 1);
