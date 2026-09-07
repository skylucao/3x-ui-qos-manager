'use strict';
(() => {
  const $ = (id) => document.getElementById(id);
  let current = null, busy = false, signedOut = false, dirty = false, needsReload = false;
  const csrf = document.querySelector('meta[name="csrf-token"]').content;
  function controls() {
    $('settings-refresh').disabled = busy || signedOut;
    $('line-fields').disabled = busy || signedOut || !current || needsReload;
    $('mail-fields').disabled = busy || signedOut || !current?.mail.enabled || needsReload;
  }
  async function request(payload) {
    const response = await fetch('api/settings', {
      method: payload ? 'POST' : 'GET', credentials: 'same-origin', cache: 'no-store',
      headers: payload ? { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf } : {},
      body: payload ? JSON.stringify(payload) : undefined,
      signal: AbortSignal.timeout(payload ? 165000 : 15000)
    });
    if (response.status === 401 || response.status === 403 || response.redirected || !response.headers.get('content-type')?.includes('application/json')) {
      signedOut = true; throw new Error('登录已失效，请返回 3x-ui 重新登录。');
    }
    const result = await response.json();
    if (!response.ok || !result.ok) throw new Error(result.message || '设置暂不可用。');
    return result;
  }
  function render(section) {
    if (!section || section === 'line') {
      $('line-mbps').value = current.line.link_mbps;
      $('reserve-mbps').value = current.line.reserved_mbps;
    }
    if (!section || section === 'mail') $('mail-time').value = current.mail.time;
    $('mail-settings-info').textContent = current.mail.enabled ? `当前保存时间：每天 ${current.mail.time}（北京时间）。发信账号继续在 3x-ui 的 SMTP 设置中管理。` : '未安装审计附加组件，邮件设置暂不可用。';
  }
  async function load() {
    if (busy || signedOut) return;
    if (dirty && !window.confirm('重新载入会丢弃此页未保存的修改，是否继续？')) return;
    busy = true; controls();
    try {
      current = await request(); render(); dirty = false; needsReload = false;
      $('settings-status').textContent = '已载入服务器设置。';
    } catch (error) { $('settings-status').textContent = error.message; }
    finally { busy = false; controls(); }
  }
  async function save(section) {
    if (busy || signedOut || !current || needsReload) return;
    const payload = { section, expected_revision: current[section].revision };
    if (section === 'line') {
      payload.link_mbps = Number($('line-mbps').value); payload.reserved_mbps = Number($('reserve-mbps').value);
      if (!Number.isInteger(payload.link_mbps) || !Number.isInteger(payload.reserved_mbps) || payload.reserved_mbps >= payload.link_mbps) {
        $('settings-status').textContent = '请填写整数 Mbps，管理预留必须小于总带宽。'; return;
      }
    } else payload.time = $('mail-time').value;
    busy = true; controls(); $('settings-status').textContent = '正在保存，请勿关闭页面…';
    try {
      const result = await request(payload);
      // Only acknowledge the saved section; preserve drafts AND revisions of the other section.
      current[section] = result[section]; render(section);
      dirty = true;
      $('settings-status').textContent = section === 'line' ? '线路带宽已保存并应用。' : '发送时间已保存，下一次到点生效。';
    } catch (error) {
      needsReload = true;
      $('settings-status').textContent = `${error.message} 保存结果未确认时，请重新载入核对后再改。`;
    } finally { busy = false; controls(); }
  }
  $('line-form').addEventListener('submit', (event) => { event.preventDefault(); save('line'); });
  $('mail-form').addEventListener('submit', (event) => { event.preventDefault(); save('mail'); });
  for (const id of ['line-mbps', 'reserve-mbps', 'mail-time']) $(id).addEventListener('input', () => { dirty = true; });
  $('settings-refresh').addEventListener('click', load);
  load();
})();
