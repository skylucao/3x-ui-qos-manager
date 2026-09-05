"use strict";

const csrf = document.querySelector('meta[name="csrf-token"]').content;
const state = {
  constraints: {link_egress_mbps: 250, reserved_mbps: 50, individual_max_mbps: 250},
  configRevision: 0,
  sampleTime: 0,
  records: new Map(),
  histories: new Map(),
  savingId: null,
  initialized: false,
};
const cards = new Map();
const cardHost = document.querySelector("#cards");
const template = document.querySelector("#card-template");

function serverDraft(node) {
  return {
    enabled: Boolean(node.limit_enabled),
    down: Number(node.limit_download_mbps ?? node.suggested_download_mbps ?? 1),
    up: Number(node.limit_upload_mbps ?? node.suggested_upload_mbps ?? 1),
  };
}

function sameDraft(left, right) {
  if (left.enabled !== right.enabled) return false;
  if (!left.enabled) return true;
  return left.down === right.down && left.up === right.up;
}

function createCard(node) {
  const id = node.id;
  const card = template.content.firstElementChild.cloneNode(true);
  const suffix = String(node.inbound_id);
  const titleId = `node-title-${suffix}`;
  const stateId = `node-state-${suffix}`;
  card.dataset.node = id;
  card.setAttribute("aria-labelledby", titleId);
  card.querySelector("h2").id = titleId;
  card.querySelector(".change-state").id = stateId;
  card.querySelector("canvas").setAttribute("aria-hidden", "true");

  for (const direction of ["down", "up"]) {
    const number = card.querySelector(`[data-input="${direction}"]`);
    const range = card.querySelector(`[data-range="${direction}"]`);
    const inputId = `node-${suffix}-${direction}`;
    number.id = inputId;
    number.setAttribute("aria-describedby", stateId);
    range.setAttribute("aria-describedby", stateId);
    card.querySelector(`[data-label="${direction}"]`).htmlFor = inputId;
    number.addEventListener("input", () => {
      const record = state.records.get(id);
      if (!record) return;
      record.draft[direction] = Number(number.value);
      if (number.value !== "") range.value = number.value;
      refreshDirty(record);
      renderControls(id);
    });
    range.addEventListener("input", () => {
      const record = state.records.get(id);
      if (!record) return;
      number.value = range.value;
      record.draft[direction] = Number(range.value);
      refreshDirty(record);
      renderControls(id);
    });
  }

  const toggle = card.querySelector('[data-input="limit-enabled"]');
  toggle.addEventListener("change", () => {
    const record = state.records.get(id);
    if (!record) return;
    record.draft.enabled = toggle.checked;
    refreshDirty(record);
    renderControls(id);
  });
  card.querySelector(".apply-button").addEventListener("click", () => saveNode(id));
  cards.set(id, card);
  cardHost.append(card);
  return card;
}

function refreshDirty(record) {
  const wasDirty = record.dirty;
  record.dirty = !sameDraft(record.draft, serverDraft(record.server));
  if (!wasDirty && record.dirty) record.editBaseRevision = state.configRevision;
  if (!record.dirty) record.editBaseRevision = null;
}

function writeDraft(id) {
  const record = state.records.get(id);
  const card = cards.get(id);
  if (!record || !card) return;
  card.querySelector('[data-input="limit-enabled"]').checked = record.draft.enabled;
  for (const direction of ["down", "up"]) {
    card.querySelector(`[data-input="${direction}"]`).value = record.draft[direction];
    card.querySelector(`[data-range="${direction}"]`).value = record.draft[direction];
  }
}

function validInteger(value, min, max) {
  return Number.isInteger(value) && value >= min && value <= max;
}

function renderControls(id) {
  const record = state.records.get(id);
  const card = cards.get(id);
  if (!record || !card) return;
  const node = record.server;
  const maximum = Number(state.constraints.individual_max_mbps || 1);
  const toggle = card.querySelector('[data-input="limit-enabled"]');
  toggle.checked = record.draft.enabled;
  toggle.disabled = record.saving || (!node.qos_supported && !record.draft.enabled);

  for (const direction of ["down", "up"]) {
    const number = card.querySelector(`[data-input="${direction}"]`);
    const range = card.querySelector(`[data-range="${direction}"]`);
    number.max = maximum;
    range.max = maximum;
    const disabled = record.saving || !node.qos_supported || !record.draft.enabled;
    number.disabled = disabled;
    range.disabled = disabled;
  }

  const valid = !record.draft.enabled || (
    validInteger(record.draft.down, 1, maximum) && validInteger(record.draft.up, 1, maximum)
  );
  const status = card.querySelector(".change-state");
  if (!node.qos_supported && record.dirty && !record.draft.enabled && node.limit_enabled) {
    status.textContent = "应用后将清除此节点的旧限速配置";
    status.className = "change-state changed-text";
  } else if (!node.qos_supported) {
    status.textContent = node.qos_reason || "当前节点不支持独立限速";
    status.className = "change-state invalid-text";
  } else if (record.saving) {
    status.textContent = "正在安全应用设置…";
    status.className = "change-state changed-text";
  } else if (!valid) {
    status.textContent = `请输入 1 到 ${formatNumber(maximum)} 的整数速度`;
    status.className = "change-state invalid-text";
  } else if (record.dirty && record.editBaseRevision !== null && record.editBaseRevision !== state.configRevision) {
    status.textContent = "服务器配置已变化，请检查后再次应用";
    status.className = "change-state invalid-text";
  } else if (record.dirty) {
    status.textContent = record.draft.enabled ? "有未保存的修改" : "应用后将取消此节点限速";
    status.className = "change-state changed-text";
  } else if (!node.inbound_enabled && node.limit_enabled) {
    status.textContent = "限速配置已保留，启用节点后自动恢复";
    status.className = "change-state";
  } else if (node.qos_mode === "pending") {
    status.textContent = "等待限速规则同步";
    status.className = "change-state changed-text";
  } else if (node.limit_enabled) {
    status.textContent = "限速已生效";
    status.className = "change-state";
  } else {
    status.textContent = "未限速，共享线路可用带宽";
    status.className = "change-state";
  }
  for (const input of card.querySelectorAll('input[type="number"]')) {
    input.setAttribute("aria-invalid", String(!valid));
  }
  const button = card.querySelector(".apply-button");
  const canApply = node.qos_supported || (!record.draft.enabled && node.limit_enabled);
  button.disabled = !valid || !record.dirty || record.saving || state.savingId !== null || !canApply;
  button.textContent = record.saving ? "正在应用…" : record.draft.enabled ? "应用此节点" : "取消此节点限速";
}

function updateSummary() {
  const link = Number(state.constraints.link_egress_mbps || 0);
  const used = Number(state.constraints.aggregate_download_mbps || 0);
  const upload = Number(state.constraints.aggregate_upload_mbps || 0);
  const free = Math.max(0, link - used);
  document.querySelector("#pool-total").textContent = formatNumber(link);
  document.querySelector("#pool-used").textContent = formatRateNumber(used);
  document.querySelector("#pool-free").textContent = formatRateNumber(free);
  document.querySelector("#pool-upload").textContent = formatRateNumber(upload);
  document.querySelector("#pool-reserved").textContent = formatNumber(Number(state.constraints.reserved_mbps || 0));
  document.querySelector("#node-count").textContent = String(state.records.size);
  const fraction = link > 0 ? Math.min(1, Math.max(0, used / link)) : 0;
  document.querySelector("#pool-fill").style.width = `${fraction * 100}%`;
  document.querySelector(".pool").classList.toggle("invalid", used > link);
  for (const id of state.records.keys()) renderControls(id);
}

function formatNumber(value) {
  return Number.isInteger(value) ? String(value) : Number(value).toFixed(1);
}

function formatRateNumber(value) {
  const number = Number(value || 0);
  return number >= 100 ? number.toFixed(0) : number.toFixed(1);
}

function formatRate(value) {
  const number = Number(value || 0);
  if (number < 0.001) return "0 Kbps";
  if (number < 1) return `${Math.round(number * 1000)} Kbps`;
  return `${number.toFixed(number >= 100 ? 0 : 1)} Mbps`;
}

function formatBytes(value) {
  const units = ["B", "KB", "MB", "GB", "TB"];
  let number = Number(value || 0);
  let index = 0;
  while (number >= 1024 && index < units.length - 1) {
    number /= 1024;
    index += 1;
  }
  const digits = index < 2 ? 0 : number >= 100 ? 0 : number >= 10 ? 1 : 2;
  return `${number.toFixed(digits)} ${units[index]}`;
}

function setText(card, key, value) {
  card.querySelector(`[data-value="${key}"]`).textContent = value;
}

function pushPoint(history, value) {
  history.push(Number(value || 0));
  if (history.length > 60) history.shift();
}

function drawChart(canvas, down, up) {
  const ratio = window.devicePixelRatio || 1;
  const rect = canvas.getBoundingClientRect();
  if (!rect.width || !rect.height) return;
  canvas.width = Math.max(1, Math.round(rect.width * ratio));
  canvas.height = Math.max(1, Math.round(rect.height * ratio));
  const context = canvas.getContext("2d");
  context.scale(ratio, ratio);
  const width = rect.width;
  const height = rect.height;
  const padding = 12;
  const maximum = Math.max(1, ...down, ...up);

  context.strokeStyle = "#22314a";
  context.lineWidth = 1;
  for (let index = 1; index < 4; index += 1) {
    const y = height * index / 4;
    context.beginPath();
    context.moveTo(0, y);
    context.lineTo(width, y);
    context.stroke();
  }
  const plot = (points, color) => {
    if (!points.length) return;
    context.beginPath();
    points.forEach((value, index) => {
      const x = padding + index * (width - padding * 2) / Math.max(1, points.length - 1);
      const y = height - padding - value / maximum * (height - padding * 2);
      if (index) context.lineTo(x, y);
      else context.moveTo(x, y);
    });
    context.strokeStyle = color;
    context.lineWidth = 2.2;
    context.lineJoin = "round";
    context.lineCap = "round";
    context.stroke();
  };
  plot(down, "#72a7ff");
  plot(up, "#52dec0");
}

function renderNode(id) {
  const record = state.records.get(id);
  const card = cards.get(id);
  if (!record || !card) return;
  const node = record.server;
  card.querySelector("h2").textContent = node.name;
  card.querySelector(".node-port").textContent = `${String(node.protocol).toUpperCase()} · 端口 ${node.port} · ID ${node.inbound_id}`;
  const badge = card.querySelector(".node-health");
  let badgeClass = "offline";
  let badgeText = "离线";
  if (!node.inbound_enabled) {
    badgeClass = "paused";
    badgeText = "3x-ui 已停用";
  } else if (!node.qos_supported) {
    badgeClass = "warning";
    badgeText = "限速不支持";
  } else if (node.online) {
    if (node.qos_mode === "pending") {
      badgeClass = "warning";
      badgeText = "在线 · 同步中";
    } else {
      badgeClass = "online";
      badgeText = node.qos_mode === "limited" ? "在线 · 已限速" : "在线 · 未限速";
    }
  }
  badge.className = `pill node-health ${badgeClass}`;
  badge.querySelector("span").textContent = badgeText;
  card.querySelector(".node-dot").classList.toggle("offline", !node.online);
  card.classList.toggle("node-disabled", !node.inbound_enabled);

  setText(card, "down-rate", formatRate(node.download_mbps));
  setText(card, "up-rate", formatRate(node.upload_mbps));
  setText(card, "down-total", formatBytes(node.total_download_bytes));
  setText(card, "up-total", formatBytes(node.total_upload_bytes));
  setText(card, "down-drops", String(node.download_drops || 0));
  setText(card, "up-drops", String(node.upload_drops || 0));
  for (const direction of ["down", "up"]) {
    const enabled = Boolean(node.limit_enabled);
    const value = direction === "down" ? node.limit_download_mbps : node.limit_upload_mbps;
    setText(card, `${direction}-limit`, enabled ? formatNumber(Number(value)) : "未限速");
    card.querySelector(`[data-unit="${direction}"]`).hidden = !enabled;
  }

  const history = state.histories.get(id);
  pushPoint(history.down, node.download_mbps);
  pushPoint(history.up, node.upload_mbps);
  drawChart(card.querySelector("canvas"), history.down, history.up);
  renderControls(id);
}

function applySnapshot(data) {
  if (!data.ok || !Array.isArray(data.nodes)) throw new Error(data.message || "状态不可用");
  const revision = Number(data.config_revision);
  const sampleTime = Number(data.sample_time_ms);
  if (revision < state.configRevision || (revision === state.configRevision && sampleTime <= state.sampleTime)) return;
  state.configRevision = revision;
  state.sampleTime = sampleTime;
  state.constraints = data.constraints;

  const health = document.querySelector("#health");
  if (data.discovery_stale) {
    health.className = "pill warning";
    health.querySelector("span").textContent = "节点数据暂不可用";
  } else if (data.message) {
    health.className = "pill warning";
    health.querySelector("span").textContent = "限速规则异常";
  } else {
    health.className = data.service_healthy ? "pill online" : "pill offline";
    health.querySelector("span").textContent = data.service_healthy ? "线路正常" : "部分节点离线";
  }

  const incoming = new Set();
  const desiredOrder = [];
  const added = [];
  for (const node of data.nodes) {
    if (typeof node.id !== "string" || !Number.isInteger(node.inbound_id)) continue;
    incoming.add(node.id);
    desiredOrder.push(node.id);
    let record = state.records.get(node.id);
    if (!record) {
      record = {server: node, draft: serverDraft(node), dirty: false, saving: false, editBaseRevision: null};
      state.records.set(node.id, record);
      state.histories.set(node.id, {down: [], up: []});
      createCard(node);
      writeDraft(node.id);
      added.push(node.name);
    } else {
      record.server = node;
      if (!record.dirty && !record.saving) {
        record.draft = serverDraft(node);
        writeDraft(node.id);
      } else {
        refreshDirty(record);
      }
    }
    renderNode(node.id);
  }

  const removed = [];
  const removedDirty = [];
  for (const [id, record] of [...state.records.entries()]) {
    if (incoming.has(id)) continue;
    removed.push(record.server.name);
    if (record.dirty) removedDirty.push(record.server.name);
    cards.get(id)?.remove();
    cards.delete(id);
    state.records.delete(id);
    state.histories.delete(id);
  }
  const currentOrder = [...cardHost.children].map((card) => card.dataset.node);
  if (currentOrder.length !== desiredOrder.length || currentOrder.some((id, index) => id !== desiredOrder[index])) {
    for (const id of desiredOrder) cardHost.append(cards.get(id));
  }
  document.querySelector("#empty-state").hidden = state.records.size !== 0;
  if (state.initialized && (added.length || removed.length)) {
    const messages = [];
    if (added.length) messages.push(`新增 ${added.length} 个节点`);
    if (removed.length) messages.push(`移除 ${removed.length} 个节点`);
    if (removedDirty.length) messages.push(`${removedDirty.length} 个节点的未保存修改已取消`);
    document.querySelector("#node-announcer").textContent = messages.join("；");
    if (removed.length) toast(messages.join("；"), true);
  }
  state.initialized = true;
  updateSummary();
}

async function poll() {
  try {
    const response = await fetch("api/status", {cache: "no-store", credentials: "same-origin"});
    if (response.status === 401) {
      location.reload();
      return;
    }
    const result = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(result.message || `HTTP ${response.status}`);
    applySnapshot(result);
  } catch (error) {
    const health = document.querySelector("#health");
    health.className = "pill offline";
    health.querySelector("span").textContent = "连接中断";
  } finally {
    setTimeout(poll, 2000);
  }
}

async function saveNode(id) {
  const record = state.records.get(id);
  if (!record || record.saving || state.savingId !== null) return;
  if (record.editBaseRevision !== null && record.editBaseRevision !== state.configRevision) {
    record.editBaseRevision = state.configRevision;
    renderControls(id);
    toast("服务器配置在编辑期间已变化；请检查数值，再点一次应用以确认", true);
    return;
  }
  const submitted = {...record.draft};
  const expectedRevision = record.editBaseRevision ?? state.configRevision;
  record.saving = true;
  state.savingId = id;
  updateSummary();
  try {
    const response = await fetch("api/set", {
      method: "POST",
      credentials: "same-origin",
      headers: {"Content-Type": "application/json", "X-CSRF-Token": csrf},
      body: JSON.stringify({
        node_id: record.server.inbound_id,
        limit_enabled: submitted.enabled,
        download_mbps: submitted.down,
        upload_mbps: submitted.up,
        expected_revision: expectedRevision,
      }),
    });
    if (response.status === 401) {
      location.reload();
      return;
    }
    const result = await response.json().catch(() => ({}));
    if (!response.ok || result.ok !== true) throw new Error(result.message || "限速保存失败");
    if (result.status) applySnapshot(result.status);
    const current = state.records.get(id);
    if (current && sameDraft(current.draft, submitted)) current.dirty = false;
    toast(result.message || "限速已更新");
  } catch (error) {
    toast(error instanceof Error ? error.message : "限速保存失败", true);
  } finally {
    const current = state.records.get(id);
    if (current) {
      current.saving = false;
      refreshDirty(current);
    }
    state.savingId = null;
    updateSummary();
  }
}

function toast(message, isError = false) {
  const element = document.querySelector("#toast");
  element.textContent = message;
  element.setAttribute("role", isError ? "alert" : "status");
  element.className = isError ? "show error" : "show";
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => { element.className = ""; }, 3000);
}

document.querySelector("#logout").addEventListener("click", async () => {
  try {
    await fetch("api/logout", {
      method: "POST",
      credentials: "same-origin",
      headers: {"X-CSRF-Token": csrf},
    });
  } finally {
    location.reload();
  }
});

addEventListener("resize", () => {
  for (const [id, card] of cards) {
    const history = state.histories.get(id);
    drawChart(card.querySelector("canvas"), history.down, history.up);
  }
});

poll();
