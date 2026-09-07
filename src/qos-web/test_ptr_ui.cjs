'use strict';
// Synthetic state test of the real audit script; no browser, DNS or employee data.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
class Element {
  constructor(tag) { this.tagName = tag; this.children = []; this.listeners = {}; this.dataset = {}; this.value = ''; this.style = { setProperty() {} }; this._text = ''; this.connected = false; }
  set isConnected(value) { this.connected = value; for (const child of this.children) child.isConnected = value; }
  get isConnected() { return this.connected; }
  set textContent(value) { this.replaceChildren(); this._text = String(value); }
  get textContent() { return this._text + this.children.map((child) => child.textContent).join(''); }
  append(...nodes) { for (const node of nodes) { node.isConnected = this.isConnected; this.children.push(node); } }
  replaceChildren(...nodes) { for (const child of this.children) child.isConnected = false; this.children = []; this._text = ''; this.append(...nodes); }
  setAttribute() {}
  addEventListener(event, callback) { this.listeners[event] = callback; }
}
const elements = new Map();
const element = (id) => { if (!elements.has(id)) { const node = new Element('div'); node.isConnected = true; elements.set(id, node); } return elements.get(id); };
const descendants = (node) => [node, ...node.children.flatMap(descendants)];
const row = () => element('target-rows').children[0];
const button = () => descendants(row()).find((node) => node.tagName === 'button');
const pending = [], requests = [];
const geoPending = [], geoRequests = [];
let holdReport = false, releaseReport;
const baseNode = { key: 'node:1', id: 1, remark: 'Test node', protocol: 'vless', port: 443, enabled: true,
  total_connections: 1, unique_destinations: 1, destinations: [{ kind: 'ip', destination: '8.8.8.8', connections: 1,
    classification: { service: '未知服务', category: '未分类', basis: '仅记录到 IP' } },
    { kind: 'ip', destination: '1.1.1.1', connections: 1 }, { kind: 'ip', destination: '10.0.0.1', connections: 1 },
    { kind: 'domain', destination: 'example.test', connections: 1 }] };
const report = { report_date: '2026-09-07', generated_at: '2026-09-07T10:00:00+08:00', kind: 'daily', total_connections: 1, node_count: 2,
  nodes: [baseNode, { ...structuredClone(baseNode), key: 'node:2', id: 2, remark: 'Second node' }] };
const response = (data) => ({ status: 200, ok: true, headers: { get: () => 'application/json' }, json: async () => structuredClone(data) });
const context = { document: { getElementById: element, createElement: (tag) => new Element(tag), querySelector: () => ({ content: 'test-csrf' }), addEventListener() {}, hidden: false },
  window: { NodeNotes: { mount() {} } }, AbortSignal, URL, setInterval() {},
  fetch: async (url, options) => {
    if (url === 'api/audit/ptr') { requests.push(options); return new Promise((resolve) => pending.push((data) => resolve(response(data)))); }
    if (url === 'api/audit/geo') { geoRequests.push(options); return new Promise((resolve) => geoPending.push({ body: JSON.parse(options.body), finish: (data, status = 200) => resolve({ ...response(data), status, ok: status === 200 }) })); }
    if (url === 'api/audit/index') return response({ today: '2026-09-07', dates: [{ report_date: '2026-09-06' }], generated_at: report.generated_at,
      current_generation_ok: true, mail: { schedule: '09:00', state: 'not_run' } });
    const data = { ...report, report_date: new URL(url, 'https://example.test/').searchParams.get('date') };
    if (holdReport) { holdReport = false; return new Promise((resolve) => { releaseReport = () => resolve(response(data)); }); }
    return response(data);
  } };
const flush = () => new Promise((resolve) => setImmediate(resolve));
const found = { status: 'found', hostname: 'dns.google', reference: { possibility: '可能关联 Google Public DNS', common_uses: '域名解析',
  basis: 'PTR 名称精确匹配 dns.google', confidence: 'low', limitation: '不能证明实际访问网站', source_url: 'https://developers.google.com/speed/public-dns/docs/doh' } };
const location = { status: 'found', location: { country: '<img src=x>', province: 'Example Province', city: null, isp: 'Example ISP', country_code: 'ZZ' }, database_date: '2026-07-09' };
const finishGeo = (job, entry = location) => job.finish({ report_date: job.body.date, node_key: job.body.node_key,
  results: { '8.8.8.8': entry, '1.1.1.1': { status: 'not_found' }, '10.0.0.1': { status: 'not_public' } } });
(async () => {
  vm.runInNewContext(fs.readFileSync(path.join(__dirname, 'static/audit.js'), 'utf8'), context);
  await flush();
  assert.equal(geoRequests.length, 1, 'geo must start automatically, one batch for all node rows');
  assert.deepEqual(JSON.parse(geoRequests[0].body), { date: '2026-09-07', node_key: 'node:1' });
  assert.equal(geoRequests[0].headers['X-CSRF-Token'], 'test-csrf');
  assert.equal(requests.length, 0, 'automatic geo must not trigger DNS PTR');
  assert.equal(descendants(row()).some((node) => node.tagName === 'button' && node.textContent === 'IP 归属地'), false);
  finishGeo(geoPending.shift()); await flush();
  assert.match(row().children[1].textContent, /Example ISP/);
  assert.match(row().children[1].textContent, /城市：未知/);
  assert.match(row().children[1].textContent, /数据库：2026-07-09/);
  assert.equal(descendants(row()).some((node) => node.tagName === 'img'), false);
  assert.match(element('target-rows').children[1].children[1].textContent, /未知归属地/);
  assert.match(element('target-rows').children[2].children[1].textContent, /非公网 IP/);
  assert.match(element('target-rows').children[3].children[1].textContent, /未记录连接 IP/);
  const click = button().listeners.click();
  assert.equal(button().disabled, true);
  assert.deepEqual(JSON.parse(requests.at(-1).body), { date: '2026-09-07', ip: '8.8.8.8' });
  assert.equal(requests.at(-1).headers['X-CSRF-Token'], 'test-csrf');
  pending.shift()(found); await click;
  assert.match(row().textContent, /可能关联 Google Public DNS/);
  assert.match(row().textContent, /可信度低/);
  assert.equal(row().children[2].textContent, '未知服务未分类', 'PTR must not replace observed classification');
  assert.equal(descendants(row()).filter((node) => node.tagName === 'a').length, 1);
  assert.equal(button().disabled, false);
  for (const source_url of ['javascript:alert(1)', 'https://evil.test/', 'https://docs.github.com.evil.test/', 'https://user@docs.github.com/', 'https://docs.github.com:444/']) {
    const request = button().listeners.click();
    pending.shift()({ ...found, hostname: '<img src=x>', reference: { ...found.reference, source_url } }); await request;
    assert.equal(descendants(row()).some((node) => node.tagName === 'a' || node.tagName === 'img'), false);
    assert.match(row().textContent, /<img src=x>/, 'hostname is text, never HTML');
  }
  let request = button().listeners.click();
  pending.shift()({ status: 'not_found', hostname: null, reference: { possibility: '无法确定具体网站 / 服务', common_uses: '当前没有依据区分', basis: '没有可用 PTR', confidence: 'unknown' } }); await request;
  assert.match(row().textContent, /无法确定/); assert.doesNotMatch(row().textContent, /Google/);
  let oldRow = row(); request = button().listeners.click();
  element('node-list').children[1].listeners.click(); pending.shift()(found); await request;
  assert.equal(oldRow.isConnected, false); assert.doesNotMatch(row().textContent, /Google Public DNS/);
  oldRow = row(); request = button().listeners.click();
  element('report-date').value = '2026-09-06'; element('report-date').listeners.change(); await flush();
  pending.shift()(found); await request;
  assert.equal(oldRow.isConnected, false); assert.doesNotMatch(row().textContent, /Google Public DNS/);
  const ptrCallsBeforeGeo = requests.length;
  finishGeo(geoPending.shift()); await flush(); // Previous date's node result.
  assert.doesNotMatch(row().textContent, /Example ISP/);
  finishGeo(geoPending.shift()); await flush(); // Current node/date result.
  assert.match(row().textContent, /Example ISP/);
  let batches = geoRequests.length;
  element('target-filter').value = '8.8'; element('target-filter').listeners.input(); await flush();
  assert.equal(geoRequests.length, batches, 'filtering reuses one result/promise per report node');
  assert.match(row().children[1].textContent, /Example ISP/);
  element('target-filter').value = 'example.test'; element('target-filter').listeners.input(); await flush();
  assert.equal(geoRequests.length, batches); assert.match(row().children[1].textContent, /未记录连接 IP/);
  element('report-date').value = '2026-09-07'; element('report-date').listeners.change(); await flush();
  oldRow = row(); element('node-list').children[0].listeners.click(); await flush();
  finishGeo(geoPending.shift()); await flush();
  assert.equal(oldRow.isConnected, false); assert.doesNotMatch(row().textContent, /Example ISP/);
  const activeJob = geoPending.shift();
  // Filtering while a batch is pending must not start duplicate requests or paint old rows.
  oldRow = row(); batches = geoRequests.length;
  element('target-filter').value = '8.8'; element('target-filter').listeners.input();
  assert.equal(geoRequests.length, batches); finishGeo(activeJob); await flush();
  assert.equal(oldRow.isConnected, false); assert.match(row().children[1].textContent, /Example ISP/);
  for (const status of ['not_found', 'not_installed', 'unavailable', 'busy']) {
    element('refresh').listeners.click(); await flush(); finishGeo(geoPending.shift(), { status }); await flush();
    assert.doesNotMatch(row().textContent, /Example ISP/);
  }
  element('refresh').listeners.click(); await flush(); geoPending.shift().finish({}, 503); await flush();
  assert.match(row().children[1].textContent, /暂不可用/);
  element('refresh').listeners.click(); await flush(); const losingSession = geoPending.shift();
  holdReport = true; element('refresh').listeners.click(); await flush();
  losingSession.finish({}, 401); await flush(); releaseReport(); await flush();
  assert.equal(element('report-content').hidden, true); assert.equal(element('target-rows').children.length, 0);
  assert.equal(requests.length, ptrCallsBeforeGeo, 'offline geo action must not also trigger DNS PTR');
  console.log('PASS: automatic batched geo, all rows, domain/private/unknown states, filter dedup, stale node/date guards, safe text, auth, manual PTR only');
})().catch((error) => { console.error(error); process.exitCode = 1; });
