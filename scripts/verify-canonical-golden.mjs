#!/usr/bin/env node
// Independent ECMAScript oracle for the accepted cross-service JCS vectors.
// Production uses the pinned Go dependency; malformed fixtures are exercised
// by Go tests so JSON.parse's permissive duplicate-key behavior is not an oracle.
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const fixturePath = process.argv[2] ?? fileURLToPath(new URL('../testdata/canonical-golden.json', import.meta.url));
const fixtures = JSON.parse(readFileSync(fixturePath, 'utf8'));

function canonical(value) {
  if (value === null) return 'null';
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new Error('nonfinite fixture number');
    return JSON.stringify(value);
  }
  if (typeof value === 'string') {
    if (!value.isWellFormed()) throw new Error('unpaired fixture surrogate');
    return JSON.stringify(value);
  }
  if (typeof value === 'boolean') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  return `{${Object.keys(value).sort().map(key => `${canonical(key)}:${canonical(value[key])}`).join(',')}}`;
}

const sha256 = bytes => createHash('sha256').update(bytes, 'utf8').digest('hex');
let checked = 0;
function verify(name, actual, expected, digest) {
  if (actual !== expected || sha256(actual) !== digest) throw new Error(`canonical fixture mismatch: ${name}`);
  checked++;
}

for (const vector of fixtures.jsonVectors) {
  verify(vector.name, canonical(JSON.parse(vector.input)), vector.canonical, vector.sha256);
}
for (const vector of fixtures.requestVectors) {
  const body = JSON.parse(vector.body);
  delete body.requestId;
  const actual = canonical({ operation: vector.operation, problemId: vector.problemId, body });
  verify(vector.name, actual, vector.canonical, vector.sha256);
}
for (const vector of fixtures.sourceVectors) {
  if (!vector.source.isWellFormed() || sha256(vector.source) !== vector.sha256) {
    throw new Error(`source fixture mismatch: ${vector.name}`);
  }
  checked++;
}
for (const vector of fixtures.byteVectors) {
  if (sha256(Buffer.from(vector.inputBase64, 'base64')) !== vector.sha256) {
    throw new Error(`binary fixture mismatch: ${vector.name}`);
  }
  checked++;
}
console.log(`Canonical golden vectors verified independently with ECMAScript: ${checked}`);
