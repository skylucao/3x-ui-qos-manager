'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const elements = new Map();
function element(id) {
  if (!elements.has(id)) elements.set(id, { value: '', disabled: false, textContent: '', listeners: {},
    addEventListener(event, callback) { this.listeners[event] = callback; } });
  return elements.get(id);
}
const state = { ok: true, line: { link_mbps: 1000, reserved_mbps: 50, revision: 'line-1' },
  mail: { enabled: true, time: '09:00', revision: 'mail-1' } };
const requests = [];
let rejectNext = false, confirm = true;
const context = {
  document: { getElementById: element, querySelector: () => ({ content: 'test-csrf' }) },
  window: { confirm: () => confirm }, AbortSignal,
  fetch: async (url, options) => {
    requests.push(options);
    if (rejectNext) { rejectNext = false; return { status: 409, ok: false, headers: { get: () => 'application/json' }, json: async () => ({ message: '版本冲突' }) }; }
    if (options.body) {
      const body = JSON.parse(options.body);
      if (body.section === 'mail') state.mail = { enabled: true, time: body.time, revision: 'mail-2' };
      else state.line = { link_mbps: body.link_mbps, reserved_mbps: body.reserved_mbps, revision: 'line-2' };
    }
    return { status: 200, ok: true, headers: { get: () => 'application/json' }, json: async () => structuredClone(state) };
  }
};
const flush = () => new Promise((resolve) => setImmediate(resolve));
const event = { preventDefault() {} };
(async () => {
  vm.runInNewContext(fs.readFileSync(path.join(__dirname, 'static/settings.js'), 'utf8'), context);
  await flush(); assert.equal(element('line-mbps').value, 1000); assert.equal(element('mail-fields').disabled, false);
  element('line-mbps').value = '900'; element('line-mbps').listeners.input();
  element('mail-time').value = '16:00'; element('mail-time').listeners.input();
  element('mail-form').listeners.submit(event); await flush();
  assert.equal(element('line-mbps').value, '900', 'saving mail must preserve line draft');
  assert.equal(element('mail-time').value, '16:00');
  element('line-form').listeners.submit(event); await flush();
  const saved = JSON.parse(requests.at(-1).body);
  assert.equal(saved.expected_revision, 'line-1', 'saving mail must not acknowledge unseen line revision');
  assert.equal(saved.link_mbps, 900); assert.equal(requests.at(-1).headers['X-CSRF-Token'], 'test-csrf');
  rejectNext = true;
  element('mail-time').value = '17:00'; element('mail-form').listeners.submit(event); await flush();
  assert.equal(element('mail-time').value, '17:00'); assert.equal(element('mail-fields').disabled, true);
  assert.match(element('settings-status').textContent, /版本冲突/);
  confirm = false; const count = requests.length; element('settings-refresh').listeners.click(); await flush();
  assert.equal(requests.length, count, 'cancelled reload keeps drafts');
  confirm = true; element('settings-refresh').listeners.click(); await flush();
  assert.equal(element('mail-time').value, '16:00'); assert.equal(element('mail-fields').disabled, false);
  console.log('PASS: settings drafts, independent revisions, CSRF, conflict and reload');
})().catch((error) => { console.error(error); process.exitCode = 1; });
