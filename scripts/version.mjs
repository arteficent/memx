#!/usr/bin/env node
// Cargo.toml is the version source; Tauri embeds it as the exe FileVersion/ProductVersion.
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));
const path = (file) => `${root}${file}`;
const read = (file) => readFileSync(path(file), 'utf8');
const semver = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;
const cargoVersion = /^(\[package\][^[]*?^version\s*=\s*")([^"]+)(")/ms;
const lockVersion = /(\[\[package\]\]\r?\nname = "memx"\r?\nversion = ")([^"]+)(")/;

function versions() {
  const packageJson = JSON.parse(read('package.json'));
  const lock = JSON.parse(read('package-lock.json'));
  return {
    'Cargo.toml': read('Cargo.toml').match(cargoVersion)?.[2],
    'Cargo.lock': read('Cargo.lock').match(lockVersion)?.[2],
    'package.json': packageJson.version,
    'package-lock.json': lock.version,
    'package-lock.json packages[""]': lock.packages?.['']?.version,
  };
}

function check() {
  const found = versions();
  const version = found['Cargo.toml'];
  if (!version || !semver.test(version)) throw new Error(`Cargo.toml version "${version}" is not semantic versioning`);
  const mismatched = Object.entries(found).filter(([, value]) => value !== version);
  if (mismatched.length) {
    throw new Error(`Version mismatch with Cargo.toml ${version}: ${mismatched.map(([file, value]) => `${file}=${value}`).join(', ')}. Run: npm run version:set -- ${version}`);
  }
  if ('version' in JSON.parse(read('tauri.conf.json'))) throw new Error('tauri.conf.json must not set "version"; Tauri reads Cargo.toml');
  return version;
}

function replace(file, pattern, version) {
  const text = read(file);
  if (!pattern.test(text)) throw new Error(`No version field found in ${file}`);
  writeFileSync(path(file), text.replace(pattern, `$1${version}$3`));
}

function set(version) {
  if (!semver.test(version ?? '')) throw new Error('Usage: npm run version:set -- <major.minor.patch[-prerelease]>');
  replace('Cargo.toml', cargoVersion, version);
  replace('Cargo.lock', lockVersion, version);
  for (const file of ['package.json', 'package-lock.json']) {
    const json = JSON.parse(read(file));
    json.version = version;
    if (json.packages?.['']) json.packages[''].version = version;
    writeFileSync(path(file), `${JSON.stringify(json, null, 2)}\n`);
  }
  return check();
}

try {
  const [command = 'check', value] = process.argv.slice(2);
  if (command === 'check') console.log(check());
  else if (command === 'set') console.log(set(value));
  else throw new Error(`Unknown command "${command}" (expected check or set)`);
} catch (error) {
  console.error(`error: ${error.message}`);
  process.exit(1);
}
