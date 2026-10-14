// One npm authority. Caller data is JSON, never script/argv/module configuration.
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const MAX = 2 * 1024 * 1024;
let semver;
try {
  if (require('semver/package.json').version !== '7.8.5') throw new Error();
  semver = require('semver');
} catch {
  process.stdout.write(JSON.stringify({ protocol_version: 1, request_id: null,
    ok: false, error: 'pinned_dependency_unavailable' }));
  process.exit(1);
}
const fail = (code) => { throw new Error(code); };
const keys = (obj, names) => obj && typeof obj === 'object' && !Array.isArray(obj) &&
  Object.keys(obj).sort().join('|') === [...names].sort().join('|');
const string = (value) => typeof value === 'string' && value.length <= 256;
const array = (value, limit) => Array.isArray(value) && value.length <= limit;
const parse = (value) => { try { return new semver.SemVer(value); } catch { return null; } };
const canonical = (parsed) => parsed.version + (parsed.build.length ? `+${parsed.build.join('.')}` : '');
const versionInfo = (value) => {
  const parsed = parse(value);
  return { input: value, valid: parsed !== null, canonical: parsed ? canonical(parsed) : null,
    base: parsed ? `${parsed.major}.${parsed.minor}.${parsed.patch}` : null,
    prerelease: parsed ? parsed.prerelease : null };
};
const checkedVersions = (values) => {
  if (!array(values, 10000) || !values.every(string)) fail('invalid_request');
  return values;
};
const allValid = (values) => { if (!values.every((value) => parse(value))) fail('invalid_version'); };
function execute(op, args) {
  if (op === 'validate_many' || op === 'sort') {
    if (!keys(args, ['versions'])) fail('invalid_request');
    const values = checkedVersions(args.versions);
    if (op === 'validate_many') return values.map(versionInfo);
    allValid(values);
    return [...values].sort(semver.compare);
  }
  if (op === 'compare_pairs') {
    if (!keys(args, ['pairs']) || !array(args.pairs, 1000)) fail('invalid_request');
    if (!args.pairs.every((pair) => array(pair, 2) && pair.length === 2 && pair.every(string))) {
      fail('invalid_request');
    }
    allValid(args.pairs.flat());
    return args.pairs.map(([left, right]) => Math.sign(semver.compare(left, right)));
  }
  if (op === 'satisfies_many') {
    if (!keys(args, ['pairs']) || !array(args.pairs, 1000)) fail('invalid_request');
    if (!args.pairs.every((pair) => keys(pair, ['version', 'range']) &&
      string(pair.version) && string(pair.range))) fail('invalid_request');
    return args.pairs.map((pair) => {
      const validVersion = parse(pair.version) !== null;
      let validRange = false;
      try { validRange = semver.validRange(pair.range) !== null; } catch { /* invalid */ }
      return { valid_version: validVersion, valid_range: validRange,
        satisfies: validVersion && validRange ? semver.satisfies(pair.version, pair.range) : null };
    });
  }
  if (op === 'between') {
    if (!keys(args, ['versions', 'from', 'to', 'prerelease']) || !string(args.from) ||
      !string(args.to) || !['default', 'all', 'none'].includes(args.prerelease)) fail('invalid_request');
    const values = checkedVersions(args.versions);
    allValid([...values, args.from, args.to]);
    if (semver.compare(args.to, args.from) < 0) fail('downgrade');
    const ownBases = new Set([args.from, args.to].map(parse)
      .filter((value) => value.prerelease.length).map((value) => `${value.major}.${value.minor}.${value.patch}`));
    const window = values.filter((value) => semver.compare(value, args.from) > 0 &&
      semver.compare(value, args.to) <= 0).sort(semver.compare);
    const selected = window.filter((value) => {
      const item = parse(value);
      if (!item.prerelease.length || args.prerelease === 'all') return true;
      if (canonical(item) === canonical(parse(args.to))) return true;
      return args.prerelease === 'default' && ownBases.has(`${item.major}.${item.minor}.${item.patch}`);
    });
    return { selected: selected.slice(0, 500), selected_total: selected.length,
      excluded_prereleases: window.length - selected.length, complete: selected.length <= 500 };
  }
  fail('unknown_operation');
}
let size = 0, oversized = false, chunks = [];
process.stdin.on('data', (chunk) => {
  size += chunk.length;
  if (size > MAX) { oversized = true; chunks = []; } else if (!oversized) chunks.push(chunk);
});
process.stdin.on('end', () => {
  let id = null, response;
  try {
    if (oversized) fail('request_limit');
    const request = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    if (!keys(request, ['protocol_version', 'request_id', 'operation', 'args']) ||
      request.protocol_version !== 1 || typeof request.request_id !== 'string' ||
      !/^[a-zA-Z0-9_-]{1,64}$/.test(request.request_id) || typeof request.operation !== 'string') {
      fail('invalid_request');
    }
    id = request.request_id;
    response = { protocol_version: 1, request_id: id, ok: true,
      result: execute(request.operation, request.args) };
  } catch (error) {
    const allowed = new Set(['invalid_request', 'invalid_version', 'downgrade', 'unknown_operation', 'request_limit']);
    response = { protocol_version: 1, request_id: id, ok: false,
      error: allowed.has(error.message) ? error.message : 'invalid_request' };
  }
  let encoded = JSON.stringify(response);
  if (Buffer.byteLength(encoded, 'utf8') > MAX) encoded = JSON.stringify({
    protocol_version: 1, request_id: id, ok: false, error: 'response_limit' });
  process.stdout.write(encoded);
});
