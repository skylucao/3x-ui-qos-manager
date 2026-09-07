// Isolated state/HTTP tests with synthetic elements, not browser or visual QA.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
class Element {
  constructor(tag) { this.tag = tag; this.children = []; this.value = ''; this.isConnected = true; this.handlers = {}; this.classList = {add() {}}; }
  append(...nodes) { this.children.push(...nodes); }
  replaceChildren(...nodes) { this.children = nodes; }
  setAttribute() {}
  addEventListener(name, handler) { this.handlers[name] = handler; }
}
const requests = [];
const context = {window: {}, document: {hidden: false, createElement: (tag) => new Element(tag), addEventListener() {}, querySelector: () => ({content: 'csrf'})},
  AbortSignal, setInterval() {}, console,
  fetch: (url, options) => new Promise((resolve) => requests.push({url, options, resolve}))};
vm.createContext(context);
vm.runInContext(fs.readFileSync(path.join(__dirname, 'static/notes.js'), 'utf8'), context);
const settle = () => new Promise(setImmediate);
const node = {key: '1:443:vless', node_id: 1, port: 443, protocol: 'vless', note: 'A', revision: 1};
function reply(request, status, payload) { request.resolve({ok: status === 200, status, redirected: false, json: async () => payload}); }
async function main() {
  const host = new Element('div');
  context.window.NodeNotes.mount(host, {id: '1', port: 443, protocol: 'vless'});
  reply(requests.shift(), 200, {ok: true, nodes: [node]}); await settle();
  const input = host.children[0].children[0];
  const [save, reset, status] = host.children[1].children;
  assert.equal(input.value, 'A');
  input.value = 'B'; input.handlers.input();
  const saving = save.handlers.click(); const post = requests.shift();
  assert.equal(JSON.parse(post.options.body).expected_revision, 1);
  const polling = context.window.NodeNotes.refresh(true);
  reply(requests.shift(), 200, {ok: true, nodes: [{...node, note: 'C', revision: 3}]}); await polling;
  reply(post, 200, {ok: true, node: {...node, note: 'B', revision: 2}}); await saving;
  assert.equal(input.value, 'B', 'keep submitted draft on a newer remote version');
  assert.match(status.textContent, /其他页面更新/);
  const resetting = reset.handlers.click();
  reply(requests.shift(), 200, {ok: true, nodes: [{...node, note: 'C', revision: 3}]}); await resetting;
  assert.equal(input.value, 'C', 'late POST must not roll back the remote version');
  input.value = 'D'; input.handlers.input();
  const savingD = save.handlers.click(); const postD = requests.shift();
  assert.equal(JSON.parse(postD.options.body).expected_revision, 3);
  reply(postD, 200, {ok: true, node: {...node, note: 'D', revision: 4}}); await savingD;
  const stalePoll = context.window.NodeNotes.refresh(true);
  reply(requests.shift(), 200, {ok: true, nodes: [{...node, note: 'C', revision: 3}]}); await stalePoll;
  assert.equal(input.value, 'D', 'late GET must not roll back the remote version');
  input.value = '😀'.repeat(200); input.handlers.input();
  assert.equal(save.disabled, false);
  assert.equal(input.maxLength, 400);
  input.value = '😀'.repeat(201); input.handlers.input();
  assert.equal(save.disabled, true);
  assert.match(status.textContent, /201/);
  console.log('PASS: draft preservation, late POST/GET, versioned save, reset, Unicode length');
}
main().catch((error) => { console.error(error); process.exitCode = 1; });
