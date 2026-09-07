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
const geoButton = () => descendants(row()).find((node) => node.tagName === 'button' && node.textContent === 'IP 归属地');
const pending = [], requests = [];
const geoPending = [], geoRequests = [];
const baseNode = { key: 'node:1', id: 1, remark: 'Test node', protocol: 'vless', port: 443, enabled: true,
  total_connections: 1, unique_destinations: 1, destinations: [{ kind: 'ip', destination: '8.8.8.8', connections: 1,
    classification: { service: '未知服务', category: '未分类', basis: '仅记录到 IP' } }] };
const report = { report_date: '2026-09-07', generated_at: '2026-09-07T10:00:00+08:00', kind: 'daily', total_connections: 1, node_count: 2,
  nodes: [baseNode, { ...structuredClone(baseNode), key: 'node:2', id: 2, remark: 'Second node' }] };
const response = (data) => ({ status: 200, ok: true, headers: { get: () => 'application/json' }, json: async () => structuredClone(data) });
const context = { document: { getElementById: element, createElement: (tag) => new Element(tag), querySelector: () => ({ content: 'test-csrf' }), addEventListener() {}, hidden: false },
  window: { NodeNotes: { mount() {} } }, AbortSignal, URL, setInterval() {},
  fetch: async (url, options) => {
    if (url === 'api/audit/ptr') { requests.push(options); return new Promise((resolve) => pending.push((data) => resolve(response(data)))); }
    if (url === 'api/audit/geo') { geoRequests.push(options); return new Promise((resolve) => geoPending.push((data) => resolve(response(data)))); }
    if (url === 'api/audit/index') return response({ today: '2026-09-07', dates: [{ report_date: '2026-09-06' }], generated_at: report.generated_at,
      current_generation_ok: true, mail: { schedule: '09:00', state: 'not_run' } });
    return response({ ...report, report_date: new URL(url, 'https://example.test/').searchParams.get('date') });
  } };
const flush = () => new Promise((resolve) => setImmediate(resolve));
const found = { status: 'found', hostname: 'dns.google', reference: { possibility: '可能关联 Google Public DNS', common_uses: '域名解析',
  basis: 'PTR 名称精确匹配 dns.google', confidence: 'low', limitation: '不能证明实际访问网站', source_url: 'https://developers.google.com/speed/public-dns/docs/doh' } };
(async () => {
  vm.runInNewContext(fs.readFileSync(path.join(__dirname, 'static/audit.js'), 'utf8'), context);
  await flush();
  const click = button().listeners.click();
  assert.equal(button().disabled, true);
  assert.deepEqual(JSON.parse(requests.at(-1).body), { date: '2026-09-07', ip: '8.8.8.8' });
  assert.equal(requests.at(-1).headers['X-CSRF-Token'], 'test-csrf');
  pending.shift()(found); await click;
  assert.match(row().textContent, /可能关联 Google Public DNS/);
  assert.match(row().textContent, /可信度低/);
  assert.equal(row().children[1].textContent, '未知服务未分类', 'PTR must not replace observed classification');
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
  const location = { status: 'found', location: { country: '<img src=x>', province: 'Example Province', city: null, isp: 'Example ISP', country_code: 'ZZ' },
    database_date: '2026-07-09', dataset_version: 'v3.17.0', source_url: 'https://evil.test/' };
  const ptrCallsBeforeGeo = requests.length;
  request = geoButton().listeners.click();
  assert.equal(geoButton().disabled, true);
  assert.equal(geoRequests.at(-1).headers['X-CSRF-Token'], 'test-csrf');
  assert.deepEqual(JSON.parse(geoRequests.at(-1).body), { date: '2026-09-06', ip: '8.8.8.8' });
  geoPending.shift()(location); await request;
  assert.equal(geoButton().disabled, false);
  assert.match(row().textContent, /城市：未知/); assert.match(row().textContent, /不是员工所在地/);
  assert.match(row().textContent, /2026-07-09（非查询日期）/);
  assert.match(row().textContent, /<img src=x>/);
  assert.equal(descendants(row()).some((node) => node.tagName === 'img'), false);
  assert.equal(row().children[1].textContent, '未知服务未分类');
  assert.equal(descendants(row()).filter((node) => node.tagName === 'a').at(-1).href, 'https://github.com/lionsoul2014/ip2region');
  for (const status of ['not_found', 'not_installed', 'unavailable', 'busy']) {
    request = geoButton().listeners.click(); geoPending.shift()({ status }); await request;
    assert.doesNotMatch(row().textContent, /Example ISP/);
  }
  oldRow = row(); request = geoButton().listeners.click();
  element('node-list').children[1].listeners.click(); geoPending.shift()(location); await request;
  assert.equal(oldRow.isConnected, false); assert.doesNotMatch(row().textContent, /Example ISP/);
  oldRow = row(); request = geoButton().listeners.click();
  element('report-date').value = '2026-09-07'; element('report-date').listeners.change(); await flush();
  geoPending.shift()(location); await request;
  assert.equal(oldRow.isConnected, false); assert.doesNotMatch(row().textContent, /Example ISP/);
  assert.equal(requests.length, ptrCallsBeforeGeo, 'offline geo action must not also trigger DNS PTR');
  console.log('PASS: PTR/geo references, safe text/links, unknown/errors, CSRF, stale node/date guards, geo independent from DNS');
})().catch((error) => { console.error(error); process.exitCode = 1; });
