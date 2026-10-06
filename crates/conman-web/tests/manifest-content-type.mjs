import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import vm from 'node:vm';

const source = await readFile(new URL('../assets/bootstrap.js', import.meta.url), 'utf8');
const start = source.indexOf('function isJsonContentType(');
assert.notEqual(start, -1, 'bootstrap must define the tested media type predicate');
const end = source.indexOf('\n}', start);
assert.notEqual(end, -1, 'media type predicate must be closed');
const predicateSource = source.slice(start, end + 2);
const isJsonContentType = vm.runInNewContext(`(${predicateSource})`);

for (const valid of [
  'application/json',
  'Application/JSON',
  ' application/json ; charset=utf-8',
  'APPLICATION/JSON; charset=UTF-8',
]) {
  assert.equal(isJsonContentType(valid), true, `expected valid JSON media type: ${valid}`);
}
for (const invalid of [
  'application/jsonp',
  'application/json-seq',
  'application/jsonfoo; charset=utf-8',
  'text/application/json',
  null,
  undefined,
]) {
  assert.equal(isJsonContentType(invalid), false, `expected invalid JSON media type: ${invalid}`);
}

console.log('manifest Content-Type contract passed');
