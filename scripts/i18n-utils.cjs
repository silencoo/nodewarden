const fs = require('fs');
const path = require('path');
const vm = require('vm');

// CONTRACT:
// This list is the script-side locale source of truth. Keep it in sync with
// webapp/src/lib/i18n.ts whenever adding/removing a locale.
const localeDir = path.join(__dirname, '..', 'webapp', 'src', 'lib', 'i18n', 'locales');

const localeFiles = [
  ['en', 'en.ts', 'en', 'English'],
  ['zh-CN', 'zh-CN.ts', 'zhCN', 'Simplified Chinese'],
  ['zh-TW', 'zh-TW.ts', 'zhTW', 'Traditional Chinese'],
  ['ru', 'ru.ts', 'ru', 'Russian'],
  ['es', 'es.ts', 'es', 'Spanish'],
  ['fi', 'fi.ts', 'fi', 'Finnish'],
  ['de', 'de.ts', 'de', 'German'],
  ['fr', 'fr.ts', 'fr', 'French'],
  ['it', 'it.ts', 'it', 'Italian'],
  ['sv', 'sv.ts', 'sv', 'Swedish'],
];

const localePaths = new Map([
  ['en.ts', path.join(localeDir, 'en.ts')],
  ['zh-CN.ts', path.join(localeDir, 'zh-CN.ts')],
  ['zh-TW.ts', path.join(localeDir, 'zh-TW.ts')],
  ['ru.ts', path.join(localeDir, 'ru.ts')],
  ['es.ts', path.join(localeDir, 'es.ts')],
  ['fi.ts', path.join(localeDir, 'fi.ts')],
  ['de.ts', path.join(localeDir, 'de.ts')],
  ['fr.ts', path.join(localeDir, 'fr.ts')],
  ['it.ts', path.join(localeDir, 'it.ts')],
  ['sv.ts', path.join(localeDir, 'sv.ts')],
]);

function getLocalePath(fileName) {
  const localePath = localePaths.get(fileName);
  if (!localePath) throw new Error(`Unsupported locale file: ${fileName}`);
  return localePath;
}

function readLocale(fileName, variableName) {
  let code = fs.readFileSync(getLocalePath(fileName), 'utf8');
  code = code
    .replace(/const (\w+): Record<string, string> =/g, 'const $1 =')
    .replace(/export default \w+;\s*$/m, '');
  code += `\nresult = ${variableName};`;
  const sandbox = { result: null };
  vm.createContext(sandbox);
  vm.runInContext(code, sandbox, { filename: fileName });
  return sandbox.result;
}

function writeLocale(fileName, variableName, table, header) {
  const body = JSON.stringify(table, null, 2);
  fs.writeFileSync(
    getLocalePath(fileName),
    `${header}\nconst ${variableName}: Record<string, string> = ${body};\n\nexport default ${variableName};\n`,
    'utf8'
  );
}

module.exports = {
  localeFiles,
  localeDir,
  readLocale,
  writeLocale,
};
