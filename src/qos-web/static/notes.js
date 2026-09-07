'use strict';
// Durable state lives on the server; only unsaved drafts live in this page.
window.NodeNotes = (() => {
  const records = new Map(), views = new Map();
  let pending = null, lastFetch = 0, available = false;
  const make = (tag, text, className) => { const node = document.createElement(tag); node.textContent = text; if (className) node.className = className; return node; };
  const keyOf = (node) => `${Number(node.inbound_id ?? node.id)}:${node.port}:${node.protocol}`;
  function update(server) {
    let record = records.get(server.key);
    if (!record) {
      record = { server, draft: server.note, base: server.revision, saving: false, error: '' }; records.set(server.key, record);
    } else {
      if (server.revision < record.server.revision) return record;
      if (record.draft === record.server.note && !record.saving) { record.draft = server.note; record.base = server.revision; }
      record.server = server;
    }
    return record;
  }
  function render(host) {
    const view = views.get(host), record = records.get(view.key);
    const disabled = !available || !record || !view.present;
    if (disabled) {
      view.status.textContent = !available ? '备注读取中或暂不可用，请稍后刷新。' : '当前节点已删除或端口/协议已变化，暂不关联备注。';
      view.input.disabled = true; view.save.disabled = true; view.reset.disabled = true;
      return;
    }
    if (view.input.value !== record.draft) view.input.value = record.draft;
    const dirty = record.draft !== record.server.note;
    const length = Array.from(record.draft).length;
    view.input.disabled = record.saving;
    view.save.disabled = record.saving || !dirty || length > 200;
    view.reset.disabled = record.saving || (!dirty && !record.error);
    view.save.textContent = record.saving ? '保存中…' : '保存备注';
    view.status.textContent = record.error || (length > 200 ? `备注最多 200 字，当前 ${length} 字` : record.saving ? '正在保存…' : dirty ? '有未保存修改' : record.server.note ? '已保存到服务器' : '尚无备注');
  }
  async function refresh(force = false) {
    if (pending) return pending;
    if (!force && Date.now() - lastFetch < 5000) return;
    pending = (async () => {
      try {
        const response = await fetch('api/notes', {credentials: 'same-origin', cache: 'no-store', signal: AbortSignal.timeout(15000)});
        if (!response.ok || response.redirected) throw new Error('notes unavailable');
        const data = await response.json();
        if (!data.ok || !Array.isArray(data.nodes)) throw new Error('notes unavailable');
        available = true;
        const present = new Set(data.nodes.map((node) => node.key));
        data.nodes.forEach(update);
        for (const view of views.values()) view.present = present.has(view.key);
      } catch (_) { available = false; }
      finally {
        lastFetch = Date.now(); pending = null;
        for (const host of views.keys()) { if (host.isConnected) render(host); else views.delete(host); }
      }
    })();
    return pending;
  }
  async function save(host) {
    const view = views.get(host), record = records.get(view.key);
    if (!record || record.saving || !available || !view.present) return;
    record.saving = true; record.error = ''; render(host);
    const submitted = record.draft;
    try {
      const csrf = document.querySelector('meta[name="csrf-token"]').content;
      const response = await fetch('api/notes', {method: 'POST', credentials: 'same-origin', cache: 'no-store', signal: AbortSignal.timeout(15000),
        headers: {'Content-Type': 'application/json', 'X-CSRF-Token': csrf},
        body: JSON.stringify({node_id: record.server.node_id, port: record.server.port, protocol: record.server.protocol, note: submitted, expected_revision: record.base})});
      const data = await response.json();
      if (!response.ok || !data.ok) {
        if (data.current) update(data.current);
        throw new Error(data.message || '保存未能确认，请刷新核对。');
      }
      update(data.node);
      if (data.node.revision < record.server.revision) {
        record.error = '备注保存后又被其他页面更新，请先载入最新备注。';
      } else {
        record.base = data.node.revision;
        if (record.draft === submitted) record.draft = data.node.note;
      }
    } catch (error) { record.error = error instanceof Error ? error.message : '保存失败'; }
    finally { record.saving = false; for (const container of views.keys()) if (container.isConnected) render(container); }
  }
  function mount(host, node) {
    if (node.unmapped || !(node.inbound_id ?? node.id)) { host.replaceChildren(make('p', '未映射记录不关联人员备注。')); views.delete(host); return; }
    const key = keyOf(node);
    if (views.get(host)?.key === key) { render(host); return; }
    const field = make('label', '节点备注（最多 200 字）', 'note-label');
    const input = document.createElement('textarea'); input.rows = 2; input.maxLength = 400; input.placeholder = '例如：张三 · 财务部 · 公司电脑'; field.append(input);
    const actions = make('div', '', 'note-actions');
    const button = make('button', '保存备注', 'ghost-button'); button.type = 'button';
    const reset = make('button', '放弃修改 / 载入最新', 'ghost-button'); reset.type = 'button';
    const status = make('span', '', 'note-status'); status.setAttribute('role', 'status');
    actions.append(button, reset, status);
    host.replaceChildren(field, actions, make('p', '独立备注，不改节点名称。历史页显示的是当前备注，不是当天人员归属证明。', 'note-hint'));
    host.classList.add('note-editor');
    views.set(host, {key, input, save: button, reset, status, present: false});
    input.addEventListener('input', () => { const record = records.get(key); if (record) { if (record.draft === record.server.note) record.base = record.server.revision; record.draft = input.value; record.error = ''; render(host); } });
    button.addEventListener('click', () => save(host));
    reset.addEventListener('click', async () => { await refresh(true); const record = records.get(key); if (record && available) { record.draft = record.server.note; record.base = record.server.revision; record.error = ''; render(host); } });
    render(host); refresh(true);
  }
  setInterval(() => { if (views.size && !document.hidden) refresh(true); }, 30000);
  document.addEventListener('visibilitychange', () => { if (!document.hidden && views.size) refresh(true); });
  return {mount, refresh};
})();
