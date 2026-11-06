'use strict';
// Synthetic input and FileReader events, with no actual file reads or network access.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const html = fs.readFileSync(path.join(__dirname, '..', 'index.html'), 'utf8');
const start = html.indexOf('  let inputRevision = 0;');
const endMarker = "  loadSample('hype');";
const end = html.indexOf(endMarker, start);
assert.ok(start >= 0 && end > start, 'production input-handler bounds');
const inputHandlers = html.slice(start, end + endMarker.length);
const nodes = new Map();
function node(selector) {
  if (!nodes.has(selector)) nodes.set(selector, {
    value: '', textContent: '', hidden: false, attrs: {}, handlers: {},
    addEventListener(name, handler) { this.handlers[name] = handler; },
    setAttribute(name, value) { this.attrs[name] = value; },
    replaceChildren() {}, focus() {},
  });
  return nodes.get(selector);
}
node('#sampleA').textContent = 'Invented sample alpha.';
node('#sampleB').textContent = 'Invented sample beta.';
let analyses = 0;
const readers = [];
class FakeFileReader {
  constructor() { readers.push(this); }
  readAsText(file) { this.file = file; }
  finish(value) { this.result = value; this.onload(); }
  fail() { this.onerror(); }
}
vm.runInNewContext(inputHandlers, {
  $: node, FileReader: FakeFileReader, runCheck() { analyses++; }
}, { timeout: 1000 });
assert.equal(analyses, 1, 'initial sample checked once');
function selectFile(size = 20) {
  node('#fileInput').handlers.change({ target: { files: [{ size }] } });
  return readers.at(-1);
}
function type(value) {
  node('#specimen').value = value;
  node('#specimen').handlers.input();
}
// 1. A delayed file read cannot overwrite later typing.
const beforeTyping = analyses;
const oldTyped = selectFile();
type('New typed content');
oldTyped.finish('Outdated file content');
assert.equal(node('#specimen').value, 'New typed content');
assert.equal(analyses, beforeTyping, 'stale read did not trigger new report');
// 2. Newer selected file wins even if older read completes last.
const oldFile = selectFile();
const newFile = selectFile();
newFile.finish('Most recent selected file');
oldFile.finish('Earlier selected file');
assert.equal(node('#specimen').value, 'Most recent selected file');
// 3. Reset cancels an outstanding read.
const oldClear = selectFile();
node('#clearInput').handlers.click();
oldClear.finish('Outdated read after clear');
assert.equal(node('#specimen').value, '');
// 4. An example click cancels the outstanding read.
const oldSample = selectFile();
node('#sampleEvidence').handlers.click();
oldSample.finish('Outdated read after example');
assert.equal(node('#specimen').value, 'Invented sample beta.');
// 5. Explicitly checking current content cancels the outstanding read.
const oldCheck = selectFile();
node('#runCheck').handlers.click();
const checked = analyses;
oldCheck.finish('Outdated read after current check');
assert.equal(node('#specimen').value, 'Invented sample beta.');
assert.equal(analyses, checked);
// 6. An oversized replacement cancels the earlier pending file.
const oldOversize = selectFile();
const activeReaderCount = readers.length;
selectFile(3000001);
assert.equal(readers.length, activeReaderCount, 'oversized file is not read');
oldOversize.finish('Earlier file after large replacement');
assert.equal(node('#specimen').value, 'Invented sample beta.');
// 7. A current successful read works and runs exactly one analysis.
const active = selectFile();
const beforeGood = analyses;
active.finish('Latest accepted file');
assert.equal(node('#specimen').value, 'Latest accepted file');
assert.equal(analyses, beforeGood + 1);
// 8. A current file error displays a safe message without hidden file data.
const failed = selectFile();
failed.fail();
assert.match(node('#specMeta').textContent, /could not be read/i);
// 9. A stale error must not override the current editor status.
const obsoleteFailure = selectFile();
type('Preserved edit');
obsoleteFailure.fail();
assert.equal(node('#specimen').value, 'Preserved edit');
assert.notEqual(node('#specMeta').textContent,
  'The file could not be read. Paste the main content instead.');
console.log('PASS: 9 synthetic stale-file race scenarios; no external I/O');
