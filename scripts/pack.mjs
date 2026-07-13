import { createRequire } from 'module';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';

const require = createRequire(import.meta.url);
const crx3 = require('crx3');

const dir = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(dir, '..');

try {
  const info = await crx3(
    [`${root}/dist`],
    {
      keyPath: `${root}/key.pem`,
      crxOutputPath: `${root}/nothing-plugin.crx`,
    }
  );

  // crx3 ignores crxOutputPath and always outputs web-extension.crx
  const defaultOut = `${root}/web-extension.crx`;
  const targetOut = `${root}/nothing-plugin.crx`;
  if (fs.existsSync(defaultOut)) {
    fs.cpSync(defaultOut, targetOut);
    fs.rmSync(defaultOut);
  }

  console.log(`✅ CRX3 created: nothing-plugin.crx`);
  console.log(`   App ID: ${info?.appId || 'unknown'}`);
} catch (err) {
  console.error('❌ CRX3 error:', err.message);
  process.exit(1);
}
