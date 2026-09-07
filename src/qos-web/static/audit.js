'use strict';
(() => {
  const $ = (id) => document.getElementById(id);
  const number = (n) => Number(n).toLocaleString('zh-CN');
  const clock = (v) => v ? new Intl.DateTimeFormat('zh-CN', { timeZone: 'Asia/Shanghai', hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' }).format(new Date(v)) : '未记录';
  let catalog = null, current = null, selectedKey = null, busy = false, signedOut = false;
  const geoCache = new WeakMap();
  let targetGeneration = 0;
  const el = (tag, text, className) => { const node = document.createElement(tag); node.textContent = text; if (className) node.className = className; return node; };
  function ptrReference(container, result) {
    const messages = { not_found: '未查到 PTR 记录', timeout: 'DNS 查询超时', unavailable: '反查服务暂不可用', busy: '查询繁忙，请稍后重试' };
    container.replaceChildren(el('span', result.status === 'found' ? `参考主机名：${result.hostname}` : messages[result.status] || '未查到'));
    const hint = result.reference;
    if (!hint) { container.append(el('span', '仅供参考，不代表实际访问的网站。', 'audit-service-meta')); return; }
    const box = el('div', '', 'audit-ptr-hint');
    box.append(el('strong', hint.possibility), el('span', hint.common_uses, 'audit-service-meta'),
      el('span', `依据：${hint.basis} · ${hint.confidence === 'low' ? '可信度低' : '无法判断'}`, 'audit-service-meta'),
      el('span', hint.limitation, 'audit-service-meta'));
    if (hint.source_url) {
      try {
        const url = new URL(hint.source_url);
        const hosts = ['developers.google.com', 'support.google.com', 'docs.cloud.google.com', 'docs.aws.amazon.com', 'learn.microsoft.com', 'core.telegram.org', 'docs.github.com'];
        if (url.protocol === 'https:' && hosts.includes(url.hostname) && !url.username && !url.password && !url.port) {
          const link = el('a', '参考规则的官方依据', 'audit-rule-link'); link.href = url.href; link.target = '_blank'; link.rel = 'noopener noreferrer'; box.append(link);
        }
      } catch (_) { /* Never open untrusted PTR names or malformed provenance. */ }
    }
    container.append(box);
  }
  function geoReference(container, result) {
    const messages = { not_found: '未知归属地', not_installed: 'IP 数据库未安装', unavailable: '归属查询暂不可用', busy: '查询繁忙，稍后刷新', not_public: '非公网 IP，无公网归属地' };
    container.replaceChildren();
    if (result.status === 'found' && result.location) {
      const value = result.location;
      container.append(el('strong', value.country || '国家 / 地区未知'),
        el('span', `省 / 州：${value.province || '未知'} · 城市：${value.city || '未知'}`, 'audit-service-meta'),
        el('span', `网络运营商：${value.isp || '未知'}`, 'audit-service-meta'));
    } else container.append(el('span', messages[result.status] || '无法确定归属地', 'audit-service-meta'));
    if (result.database_date) container.append(el('small', `数据库：${result.database_date}`, 'audit-service-meta'));
  }
  function automaticGeo(node, rows, generation) {
    const report = current, day = report.report_date, key = selectedKey;
    const visible = () => current === report && selectedKey === key && targetGeneration === generation;
    if (!rows.length) { $('geo-status').textContent = '当前记录没有可查询的 IP；域名不会被解析成历史连接 IP。'; return; }
    $('geo-status').textContent = '正在自动加载 IP 归属地…';
    let promise = geoCache.get(node);
    if (!promise) {
      promise = (async () => {
        const response = await fetch('api/audit/geo', { method: 'POST', credentials: 'same-origin', cache: 'no-store',
          headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': document.querySelector('meta[name="csrf-token"]').content },
          body: JSON.stringify({ date: day, node_key: node.key }), signal: AbortSignal.timeout(15000) });
        if (response.status === 401 || response.status === 403 || response.redirected) {
          signedOut = true; current = null; $('report-content').hidden = true; $('node-list').replaceChildren(); $('target-rows').replaceChildren();
          $('load-status').textContent = '登录已失效，请返回 3x-ui 重新登录后打开本页面。';
          throw new Error('登录已失效');
        }
        const result = await response.json();
        if (!response.ok) throw new Error(result.message || '归属地查询暂不可用');
        if (result.report_date !== day || result.node_key !== node.key || !result.results || typeof result.results !== 'object') throw new Error('归属结果与当前记录不匹配');
        return result.results;
      })();
      geoCache.set(node, promise);
    }
    promise.then((results) => {
      if (!visible()) return;
      for (const [ip, cell] of rows) if (cell.isConnected) geoReference(cell, results[ip] || { status: 'not_found' });
      $('geo-status').textContent = `已自动更新 ${rows.length} 条 IP 记录的归属状态；未知或不可用的结果保留说明。`;
    }).catch((error) => {
      if (!visible()) return;
      for (const [, cell] of rows) if (cell.isConnected) cell.textContent = '归属地暂不可用';
      $('geo-status').textContent = (error.name === 'TimeoutError' ? '归属地加载超时。' : error.message + '。') + '请刷新汇总重试，页面也会定期自动刷新。';
    });
  }
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
    const states = { running: '日报正在生成或发送', not_run: '尚无运行记录', generated_only: '最近仅生成汇总，未请求发信；不代表邮件失败', smtp_accepted: '最近日报已由 SMTP 接收', failed: '最近日报生成或发信失败，需要检查', unknown: '暂时无法确认运行状态' };
    $('mail-status').textContent = `${value.schedule}。${states[value.state] || states.unknown}${value.report_date ? `（报告日期 ${value.report_date}）` : ''}。`;
  }
  function targets(node) {
    const generation = ++targetGeneration, geoRows = [];
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
      const target = el('td', item.destination + (item.kind === 'ip' ? '（IP）' : ''));
      const geo = el('td', item.kind === 'ip' ? '正在加载归属地…' : '未记录连接 IP，无法查归属地', 'audit-geo-cell');
      if (item.kind === 'ip') geoRows.push([item.destination, geo]);
      if (item.kind === 'ip') {
        const button = el('button', '反查 IP', 'ghost-button'); button.type = 'button';
        const reference = el('div', '按需查看 PTR 与可能服务参考', 'audit-service-meta');
        reference.setAttribute('aria-live', 'polite');
        const day = current.report_date, key = selectedKey;
        button.addEventListener('click', async () => {
          button.disabled = true; reference.textContent = '正在反查…';
          try {
            const response = await fetch('api/audit/ptr', { method: 'POST', credentials: 'same-origin', cache: 'no-store',
              headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': document.querySelector('meta[name="csrf-token"]').content },
              body: JSON.stringify({ date: day, ip: item.destination }), signal: AbortSignal.timeout(10000) });
            if (response.status === 401 || response.status === 403 || response.redirected) throw new Error('请重新登录后查询');
            const result = await response.json();
            if (!response.ok) throw new Error(result.message || '查询暂不可用');
            if (!target.isConnected || current?.report_date !== day || selectedKey !== key) return;
            ptrReference(reference, result);
          } catch (error) {
            if (target.isConnected && current?.report_date === day && selectedKey === key) reference.textContent = error.name === 'TimeoutError' ? '查询超时，请稍后重试' : error.message;
          } finally { button.disabled = false; }
        });
        const actions = el('div', '', 'audit-ip-actions'); actions.append(button);
        target.append(actions, reference);
      }
      row.append(target, geo, service, basis, el('td', number(item.connections)), el('td', `${clock(item.first_seen)} / ${clock(item.last_seen)}`), el('td', hours));
      return row;
    }));
    $('target-empty').hidden = !!items.length;
    $('target-note').textContent = (node.omitted_destinations ? `按连接数展示前 ${node.destinations.length} 个目标，另 ${number(node.omitted_destinations)} 个未展开；筛选仅作用于已展示目标。` : '按连接次数排序；未匹配规则的目标保留未知。') + (current.ruleset_version ? ` 识别规则版本 ${current.ruleset_version}。` : '');
    automaticGeo(node, geoRows, generation);
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
      const nextReport = await get('api/audit/report?date=' + encodeURIComponent($('report-date').value));
      if (signedOut) return; // A concurrent automatic geo request may have lost authentication.
      current = nextReport;
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
