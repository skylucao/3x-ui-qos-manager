'use strict';
(() => {
  const $ = (id) => document.getElementById(id);
  const number = (n) => Number(n).toLocaleString('zh-CN');
  const clock = (v) => v ? new Intl.DateTimeFormat('zh-CN', { timeZone: 'Asia/Shanghai', hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' }).format(new Date(v)) : '未记录';
  let catalog = null, current = null, selectedKey = null, busy = false, signedOut = false;
  const el = (tag, text, className) => { const node = document.createElement(tag); node.textContent = text; if (className) node.className = className; return node; };
  async function get(path) {
    const response = await fetch(path, { credentials: 'same-origin', cache: 'no-store', signal: AbortSignal.timeout(15000) });
    if (response.status === 401 || response.status === 403 || response.redirected || !response.headers.get('content-type')?.includes('application/json')) {
      signedOut = true; current = null; $('report-content').hidden = true; $('node-list').replaceChildren(); $('target-rows').replaceChildren();
      throw new Error('登录已失效，请返回 3x-ui 重新登录后打开本页面。');
    }
    const data = await response.json();
    if (!response.ok) throw new Error(data.message || data.error || '该日期尚无可用汇总。');
    return data;
  }
  function warnings() {
    const items = [];
    const stale = !catalog.current_generation_ok || Date.now() - Date.parse(catalog.generated_at) > 600000;
    if (stale) items.push('汇总更新异常或已超过 10 分钟未刷新；保留的数据不代表当前状态。');
    if (catalog.history_failures) items.push('部分历史汇总读取失败，日期列表或内容可能不完整。');
    if (current) {
      if (current.kind === 'live') items.push(current.report_date === catalog.today ? '今天尚未结束：这是当前已读取日志的部分汇总。' : '这是上次保存的临时快照，尚未由历史日报替换；不是完整日报。');
      if (current.coverage_status === 'before_collection') items.push('该日期早于采集启用时间，没有可补查的历史记录。');
      if (current.coverage_status === 'period_not_complete' && current.kind !== 'live') items.push('这份报告生成时统计日期尚未结束，只含部分记录。');
      if (current.collection_started_at && current.collection_started_at.slice(0, 10) === current.report_date) items.push('采集首日仅有启用后的记录，且可能包含管理员部署连通性测试，不能归因为员工操作。');
      if (current.data_status === 'partial_read_failure') items.push('部分日志无法完整读取，以下统计不完整。');
      if (current.data_status === 'no_matching_records') items.push('未检出匹配记录；可能是没有连接、日志缺失或未经过本服务器，不能据此判断员工没有活动。');
      if (current.unmapped_connections) items.push('存在无法映射的连接，已独立列出，不归入任何员工节点。');
      if (current.malformed_lines || current.source_warning_count) items.push('原始汇总含采集覆盖或解析提示；这里只显示可识别记录，不保证日志连续完整。');
      if (current.omitted_nodes) items.push(`页面仅显示前 ${current.nodes.length} 个节点，另 ${current.omitted_nodes} 个节点未展示。`);
    }
    $('warnings').replaceChildren(...items.map((text) => el('p', text)));
    $('warnings').hidden = !items.length;
  }
  function mail() {
    const value = catalog.mail;
    const states = { not_run: '尚无运行记录', generated_only: '最近仅生成汇总，未请求发信；不代表邮件失败', smtp_accepted: '最近日报已由 SMTP 接收', failed: '最近日报生成或发信失败，需要检查', unknown: '暂时无法确认运行状态' };
    $('mail-status').textContent = `${value.schedule}。${states[value.state] || states.unknown}${value.report_date ? `（报告日期 ${value.report_date}）` : ''}。`;
  }
  function targets(node) {
    const query = $('target-filter').value.trim().toLowerCase();
    const items = node.destinations.filter((item) => [item.destination, item.classification?.service, item.classification?.category].some((value) => value?.toLowerCase().includes(query)));
    $('target-rows').replaceChildren(...items.map((item) => {
      const row = el('tr', '');
      const association = item.classification;
      const service = el('td', association?.service || '未知服务');
      service.append(el('small', association?.category || '未分类', 'audit-service-meta'));
      const basis = el('td', association?.matched_suffix ? `匹配 ${association.matched_suffix}` : association?.basis || '旧快照尚无识别结果');
      if (association?.source_url) {
        // Only link to the provenance hosts used by our local, reviewed ruleset.
        try {
          const url = new URL(association.source_url);
          if (url.protocol === 'https:' && ['github.com', 'security.tencent.com', 'learn.microsoft.com'].includes(url.hostname) && !url.username && !url.password) {
            const link = el('a', '规则来源', 'audit-rule-link'); link.href = url.href; link.target = '_blank'; link.rel = 'noopener noreferrer'; basis.append(link);
          }
        } catch (_) { /* Invalid provenance is never opened. */ }
      }
      const hours = item.hourly_connections ? item.hourly_connections.map((n, h) => n ? `${String(h).padStart(2, '0')}时（${number(n)}条）` : '').filter(Boolean).join('、') : '旧报告未记录，不能按首末时间补推';
      row.append(el('td', item.destination + (item.kind === 'ip' ? '（IP）' : '')), service, basis, el('td', number(item.connections)), el('td', `${clock(item.first_seen)} / ${clock(item.last_seen)}`), el('td', hours));
      return row;
    }));
    $('target-empty').hidden = !!items.length;
    $('target-note').textContent = (node.omitted_destinations ? `按连接数展示前 ${node.destinations.length} 个目标，另 ${number(node.omitted_destinations)} 个未展开；筛选仅作用于已展示目标。` : '按连接次数排序；未匹配规则的目标保留未知。') + (current.ruleset_version ? ` 识别规则版本 ${current.ruleset_version}。` : '');
  }
  function detail() {
    if (!current) return;
    const node = current.nodes.find((item) => item.key === selectedKey);
    $('node-detail').hidden = !node;
    if (!node) return;
    for (const button of $('node-list').children) button.setAttribute('aria-pressed', String(button.dataset.key === selectedKey));
    $('node-name').textContent = node.remark;
    window.NodeNotes.mount($('node-note-editor'), node);
    $('node-meta').textContent = node.unmapped ? '无法确认节点归属；不展示原始标签' : `节点 ID ${node.id} · ${node.protocol.toUpperCase()} · 端口 ${node.port} · ${node.enabled ? '启用' : '停用'}`;
    $('connections').textContent = number(node.total_connections);
    $('targets').textContent = number(node.unique_destinations);
    $('range').textContent = `${clock(node.first_seen)} / ${clock(node.last_seen)}`;
    $('hour-chart').replaceChildren();
    $('hour-chart').hidden = !node.hourly_connections;
    $('hour-empty').hidden = !!node.hourly_connections;
    if (node.hourly_connections) {
      const max = Math.max(1, ...node.hourly_connections);
      const snapshotHour = Number(new Intl.DateTimeFormat('en-GB', { timeZone: 'Asia/Shanghai', hourCycle: 'h23', hour: '2-digit' }).format(new Date(current.generated_at)));
      node.hourly_connections.forEach((amount, hour) => {
        const future = current.kind === 'live' && current.report_date === current.generated_at.slice(0, 10) && hour > snapshotHour;
        const title = `${hour.toString().padStart(2, '0')}:00 — ${future ? '快照生成时尚未到达' : `${number(amount)} 条记录`}`;
        const slot = el('div', '', 'hour-slot' + (future ? ' future' : ''));
        slot.title = title; slot.tabIndex = 0; slot.setAttribute('aria-label', title);
        const bar = el('div', '', 'hour-bar'); bar.style.setProperty('--bar-height', `${Math.max(2, amount / max * 115)}px`);
        slot.append(bar, el('span', hour.toString().padStart(2, '0'), 'hour-label'));
        $('hour-chart').append(slot);
      });
    }
    targets(node);
  }
  function render() {
    $('report-content').hidden = false;
    $('report-summary').textContent = `${current.report_date} · ${current.node_count} 个节点 / 分组 · 合计 ${number(current.total_connections)} 条连接记录${current.collection_started_at ? ` · 采集启用 ${current.collection_started_at.slice(0, 10)} ${clock(current.collection_started_at)}` : ''}`;
    if (!current.nodes.some((node) => node.key === selectedKey)) selectedKey = current.nodes[0]?.key || null;
    $('node-list').replaceChildren(...current.nodes.map((node) => {
      const button = el('button', '', 'audit-node'); button.type = 'button'; button.dataset.key = node.key;
      button.append(el('strong', node.remark), el('span', `${number(node.total_connections)} 条记录 · ${node.unique_destinations} 个目标`));
      button.addEventListener('click', () => { selectedKey = node.key; $('target-filter').value = ''; detail(); });
      return button;
    }));
    detail(); warnings();
    $('updated').textContent = `数据生成于 ${current.generated_at.slice(0, 10)} ${clock(current.generated_at)}`;
    $('load-status').textContent = current.nodes.length ? '汇总已加载；页面每 2 分钟自动检查更新。' : '此日期没有可展示的节点。';
  }
  async function load() {
    if (busy || signedOut) return;
    busy = true; $('refresh').disabled = true; $('report-date').disabled = true;
    $('load-status').textContent = '正在读取汇总…';
    const selectedDate = $('report-date').value;
    try {
      catalog = await get('api/audit/index'); mail();
      const days = Array.from(new Set([catalog.today, ...catalog.dates.map((item) => item.report_date)])).sort().reverse();
      $('report-date').replaceChildren(...days.map((day) => { const option = el('option', day + (day === catalog.today ? ' · 今天（部分）' : '')); option.value = day; return option; }));
      $('report-date').value = days.includes(selectedDate) ? selectedDate : catalog.today;
      // Never keep a previous date's data on screen if this date fails to load.
      current = null; $('report-content').hidden = true; warnings();
      current = await get('api/audit/report?date=' + encodeURIComponent($('report-date').value));
      render();
    } catch (error) {
      current = null; $('report-content').hidden = true; $('updated').textContent = '';
      $('load-status').textContent = error.name === 'TimeoutError' ? '读取超时，请稍后刷新。' : error.message;
    } finally {
      busy = false; $('refresh').disabled = signedOut; $('report-date').disabled = signedOut || !catalog;
    }
  }
  $('refresh').addEventListener('click', load);
  $('report-date').addEventListener('change', () => { $('target-filter').value = ''; load(); });
  $('target-filter').addEventListener('input', () => { const node = current?.nodes.find((item) => item.key === selectedKey); if (node) targets(node); });
  document.addEventListener('visibilitychange', () => { if (!document.hidden) load(); });
  setInterval(() => { if (!document.hidden) load(); }, 120000);
  load();
})();
