import { invoke } from '@tauri-apps/api/core';
import { save } from '@tauri-apps/plugin-dialog';
import { createIcons, ArrowRight, Binary, Check, ChevronLeft, ChevronRight, Cpu, Download, Layers, LockKeyhole, RefreshCw, Search, Settings2, Shield, Undo2, Unplug, X } from 'lucide';
import '@fontsource/ibm-plex-sans/latin-400.css';
import '@fontsource/ibm-plex-sans/latin-500.css';
import '@fontsource/ibm-plex-sans/latin-600.css';
import '@fontsource/ibm-plex-mono/latin-400.css';
import './style.css';

const byId = (id) => document.getElementById(id);
const state = { processes: [], scope: 'all', selected: null, snapshot: null, view: 'regions', offset: 0, total: 0, read: null, history: [], modules: [], busy: false, symbols: false, symbolPath: '', startup: false, startupElevated: false };
const iconSet = { ArrowRight, Binary, Check, ChevronLeft, ChevronRight, Cpu, Download, Layers, LockKeyhole, RefreshCw, Search, Settings2, Shield, Undo2, Unplug, X };
const icons = () => createIcons({ icons: iconSet, attrs: { 'stroke-width': 1.6 } });
const request = (request) => invoke('memory_request', { request });
const escape = (value) => String(value ?? '').replace(/[&<>"']/g, (character) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character]);
const size = (bytes) => { if (bytes < 1024) return `${bytes} B`; const unit = Math.min(4, Math.floor(Math.log(bytes) / Math.log(1024))); return `${(bytes / 1024 ** unit).toFixed(1)} ${['B', 'KiB', 'MiB', 'GiB', 'TiB'][unit]}`; };
const address = (value) => `0x${BigInt(value).toString(16).padStart(state.snapshot?.info.pointer_size === 4 ? 8 : 16, '0')}`;

function notice(message, warning = false) {
  byId('notice').textContent = message;
  byId('notice').hidden = !message;
  byId('notice').classList.toggle('warning', warning);
}

function controls() {
  const active = !!state.snapshot && !state.busy;
  for (const id of ['detach', 'read-address', 'memory-refresh', 'symbol-load', 'process-dump']) byId(id).disabled = !active;
  for (const id of ['memory-previous', 'memory-next']) byId(id).disabled = !active || !state.read;
  byId('memory-back').disabled = !active || !state.history.length;
  byId('range-previous').disabled = !active || state.view !== 'regions' || state.offset === 0;
  byId('range-next').disabled = !active || state.view !== 'regions' || state.offset + 128 >= state.total;
  byId('process-refresh').disabled = state.busy;
  byId('settings-save').disabled = state.busy;
  byId('operation-status').textContent = state.busy ? 'Working' : 'Ready';
  document.body.classList.toggle('busy', state.busy);
}

async function task(action) {
  if (state.busy) return;
  state.busy = true;
  notice('');
  controls();
  try { await action(); } catch (error) { notice(String(error)); }
  finally { state.busy = false; controls(); }
}

function renderProcesses() {
  const filter = byId('process-search').value.toLowerCase();
  const processes = state.processes.filter((process) => (state.scope === 'all' || process.category === state.scope) && `${process.name} ${process.pid} ${process.owner ?? ''}`.toLowerCase().includes(filter));
  byId('process-count').textContent = processes.length;
  byId('process-list').innerHTML = processes.map((process) => `<button class="process-row ${state.selected?.pid === process.pid ? 'selected' : ''}" data-pid="${process.pid}" aria-label="${escape(process.name)}, PID ${process.pid}, ${escape(process.access)}" aria-pressed="${state.selected?.pid === process.pid}"><i data-lucide="${process.category === 'system' ? 'shield' : 'cpu'}"></i><span class="process-text"><strong>${escape(process.name || 'Idle')}</strong><small title="${escape(process.owner)}">${escape(process.owner ?? process.category)}<span class="access-dot ${escape(process.access)}" title="${escape(process.access)}" aria-label="${escape(process.access)}"></span></small></span><span class="pid">${process.pid}</span></button>`).join('') || '<div class="empty-state"><span>No matching processes</span></div>';
  icons();
}

function renderTarget() {
  const info = state.snapshot?.info;
  byId('target-name').textContent = info?.name || state.selected?.name || 'No process selected';
  byId('target-detail').textContent = info ? `PID ${info.pid} / ${info.pointer_size * 8}-bit / ${info.path ?? 'Path unavailable'}` : state.selected ? `PID ${state.selected.pid} / ${state.selected.access}` : 'User-mode session';
  byId('target-detail').title = info?.path ?? '';
  byId('metric-memory').textContent = state.snapshot ? size(state.snapshot.committed_bytes) : '-';
  byId('metric-regions').textContent = state.snapshot?.region_count ?? '-';
  byId('metric-modules').textContent = state.snapshot?.modules ?? '-';
  byId('metric-threads').textContent = state.snapshot?.threads ?? '-';
}

function clearMemory() {
  state.read = null;
  byId('hex-view').innerHTML = '<div class="memory-empty"><i data-lucide="binary"></i><span>No memory snapshot</span></div>';
  byId('value-list').replaceChildren();
  byId('read-summary').textContent = 'No snapshot';
  byId('value-count').textContent = '0 values';
  icons();
}

async function loadProcesses() {
  state.processes = await request({ op: 'processes' });
  byId('process-status').textContent = `${state.processes.length} running`;
  renderProcesses();
}

async function attach(process) {
  state.selected = process;
  state.snapshot = null;
  state.modules = [];
  state.history = [];
  state.offset = 0;
  clearMemory();
  byId('address').value = '';
  byId('range-list').replaceChildren();
  byId('range-empty').hidden = false;
  byId('range-count').textContent = '0 ranges';
  renderTarget();
  renderProcesses();
  state.snapshot = await request({ op: 'attach', pid: process.pid, symbols: state.symbols, symbol_path: state.symbolPath || null });
  renderTarget();
  await loadRanges();
  if (state.snapshot.warnings.length) notice(state.snapshot.warnings.join('\n'), true);
}

async function loadRanges() {
  if (!state.snapshot) return;
  let ranges;
  if (state.view === 'regions') {
    const result = await request({ op: 'regions', offset: state.offset, limit: 128, readable: byId('readable-only').checked, filter: byId('region-search').value });
    state.total = result.total;
    ranges = result.regions.map((region) => ({ base: region.base, size: region.size, name: region.label || region.kind, meta: `${region.protect || '-'} / ${region.state} / ${region.kind}` }));
  } else {
    state.modules = await request({ op: 'modules' });
    byId('symbol-module').innerHTML = state.modules.map((module) => `<option>${escape(module.name)}</option>`).join('');
    if (state.view === 'symbols') { renderRanges([], '0 symbols'); return; }
    ranges = state.modules.map((module) => ({ base: module.base, size: module.size, name: module.name, meta: module.path }));
    state.total = ranges.length;
  }
  renderRanges(ranges, `${state.total.toLocaleString()} ${state.view}${state.view === 'regions' && ranges.length ? ` / ${state.offset + 1}-${state.offset + ranges.length}` : ''}`);
}

function renderRanges(ranges, count) {
  byId('range-list').innerHTML = ranges.map((range) => `<tr><td><button class="range-row" data-address="${escape(range.base)}" title="${escape(range.meta)}"><span class="mono">${escape(address(range.base))}</span><strong>${escape(range.name)}</strong><small>${escape(range.meta)}</small></button></td><td class="range-size">${size(range.size)}</td></tr>`).join('');
  byId('range-empty').hidden = ranges.length > 0;
  byId('range-count').textContent = count;
}

async function readMemory(expression = byId('address').value, remember = true) {
  const previous = state.read?.address;
  clearMemory();
  const len = Number(byId('read-length').value);
  if (!Number.isInteger(len) || len < 1 || len > 4096) throw new Error('Read length must be 1-4096 bytes');
  const result = await request({ op: 'read', address: expression, len, data_type: byId('data-type').value });
  if (remember && previous && previous !== result.address) state.history.push(previous);
  state.read = result;
  byId('address').value = result.address;
  byId('read-summary').textContent = `${result.valid_count} / ${result.bytes.length} readable bytes`;
  byId('value-count').textContent = `${result.values.length} values`;
  byId('snapshot-time').textContent = `Read at ${new Date().toLocaleTimeString()}`;
  const hexRows = [];
  for (let offset = 0; offset < result.bytes.length; offset += 16) {
    const bytes = result.bytes.slice(offset, offset + 16);
    const hex = bytes.map((byte, index) => `<span class="${byte === null ? 'unreadable' : byte === 0 ? 'zero' : ''} ${index === 8 ? 'half' : ''}">${byte === null ? '??' : byte.toString(16).padStart(2, '0')}</span>`).join('');
    const ascii = bytes.map((byte) => byte === null ? '?' : byte >= 32 && byte <= 126 ? String.fromCharCode(byte) : '.').join('');
    hexRows.push(`<div class="hex-row"><span class="hex-address">${escape(address(BigInt(result.address) + BigInt(offset)))}</span><span class="hex-bytes">${hex}</span><span class="hex-ascii">${escape(ascii)}</span></div>`);
  }
  byId('hex-view').innerHTML = hexRows.join('');
  byId('value-list').innerHTML = result.values.map((value) => {
    const pointer = /ptr|\*$/.test(value.type) ? value.value.match(/0x[\da-f]+/i)?.[0] : null;
    return `<tr><td><span class="mono">${escape(address(value.addr))}</span><small>${escape(value.type)}${value.field ? ` / ${escape(value.field)}` : ''}</small></td><td class="decoded-value">${escape(value.value)}${pointer ? `<button class="icon-button follow-pointer" data-address="${pointer}" aria-label="Follow pointer ${pointer}" title="Follow pointer"><i data-lucide="arrow-right"></i></button>` : ''}</td><td><span class="source-tag ${escape(value.source)}">${escape(value.source)}</span><small>${escape(value.confidence)}</small></td></tr>`;
  }).join('');
  if (!result.valid_count) notice('Address range is unreadable, guarded, or the process has exited.', true);
  else if (result.warnings.length) notice(result.warnings.join('\n'), true);
  icons();
}

byId('process-refresh').addEventListener('click', () => task(loadProcesses));
byId('process-dump').addEventListener('click', () => task(async () => {
  const path = await save({ title: 'Capture Process Memory', defaultPath: `memx-${state.snapshot.info.pid}-${Date.now()}.dmp`, filters: [{ name: 'Process dump', extensions: ['dmp'] }] });
  if (!path) return;
  byId('operation-status').textContent = 'Capturing process dump';
  const report = await request({ op: 'dump', path });
  notice(`Saved ${size(report.bytes)} to ${report.path}\nCaptured ${new Date(report.capture_started_unix_ms).toLocaleString()}\n${report.warnings.join('\n')}`, true);
}));
byId('process-search').addEventListener('input', renderProcesses);
document.querySelectorAll('[data-scope]').forEach((button) => button.addEventListener('click', () => { state.scope = button.dataset.scope; document.querySelectorAll('[data-scope]').forEach((item) => item.setAttribute('aria-pressed', String(item === button))); renderProcesses(); }));
byId('process-list').addEventListener('click', (event) => { const row = event.target.closest('[data-pid]'); if (row) task(() => attach(state.processes.find((process) => process.pid === Number(row.dataset.pid)))); });
byId('detach').addEventListener('click', () => task(async () => { await request({ op: 'detach' }); state.selected = null; state.snapshot = null; state.history = []; clearMemory(); renderTarget(); renderProcesses(); byId('range-list').replaceChildren(); byId('range-empty').hidden = false; byId('range-count').textContent = '0 ranges'; }));
document.querySelectorAll('[data-view]').forEach((button) => button.addEventListener('click', () => task(async () => { state.view = button.dataset.view; state.offset = 0; document.querySelectorAll('[data-view]').forEach((item) => item.setAttribute('aria-selected', String(item === button))); byId('region-controls').hidden = state.view !== 'regions'; byId('symbol-controls').hidden = state.view !== 'symbols'; await loadRanges(); })));
byId('region-search').addEventListener('change', () => task(async () => { state.offset = 0; await loadRanges(); }));
byId('readable-only').addEventListener('change', () => task(async () => { state.offset = 0; await loadRanges(); }));
for (const [id, direction] of [['range-previous', -1], ['range-next', 1]]) byId(id).addEventListener('click', () => task(async () => { state.offset = Math.max(0, state.offset + direction * 128); await loadRanges(); }));
byId('range-list').addEventListener('click', (event) => { const row = event.target.closest('[data-address]'); if (row) task(() => readMemory(row.dataset.address)); });
byId('value-list').addEventListener('click', (event) => { const row = event.target.closest('[data-address]'); if (row) task(() => readMemory(row.dataset.address)); });
byId('address-form').addEventListener('submit', (event) => { event.preventDefault(); if (state.snapshot) task(() => readMemory()); });
byId('data-type').addEventListener('change', () => { if (state.read) task(() => readMemory()); });
byId('read-length').addEventListener('change', () => { if (state.read) task(() => readMemory()); });
byId('memory-back').addEventListener('click', () => task(() => readMemory(state.history.pop(), false)));
for (const [id, direction] of [['memory-previous', -1n], ['memory-next', 1n]]) byId(id).addEventListener('click', () => task(() => { const next = BigInt(state.read.address) + direction * BigInt(byId('read-length').value); if (next < 0n) throw new Error('Start of address space'); return readMemory(`0x${next.toString(16)}`); }));
byId('memory-refresh').addEventListener('click', () => task(async () => { const current = state.read?.address; clearMemory(); state.snapshot = await request({ op: 'refresh' }); renderTarget(); await loadRanges(); if (current) await readMemory(current, false); }));
byId('symbol-load').addEventListener('click', () => task(async () => { const result = await request({ op: 'globals', module: byId('symbol-module').value, filter: byId('symbol-filter').value }); renderRanges(result.symbols.map((symbol) => ({ base: symbol.address, size: symbol.size, name: symbol.name, meta: symbol.type?.name ?? symbol.type?.kind ?? 'Type unavailable' })), `${result.total} symbols${result.total > 256 ? ' / first 256' : ''}`); if (result.warnings.length) notice(result.warnings.join('\n'), true); }));
byId('settings-open').addEventListener('click', () => { byId('settings-dialog').showModal(); task(async () => { const status = await invoke('startup_status'); state.startup = status.enabled; state.startupElevated = status.launch_elevated; byId('startup-enabled').checked = status.enabled; byId('startup-status').textContent = status.enabled ? status.launch_elevated ? 'Highest privileges / current user' : 'Legacy non-elevated startup entry' : 'Disabled for current user'; }); });
byId('settings-close').addEventListener('click', () => byId('settings-dialog').close());
byId('settings-form').addEventListener('submit', (event) => { event.preventDefault(); task(async () => { byId('settings-error').hidden = true; try { const enabled = byId('startup-enabled').checked; if (enabled !== state.startup || (enabled && !state.startupElevated)) { const status = await invoke('startup_set', { enabled }); state.startup = status.enabled; state.startupElevated = status.launch_elevated; } const changed = state.symbols !== byId('symbols-enabled').checked || state.symbolPath !== byId('symbol-path').value; state.symbols = byId('symbols-enabled').checked; state.symbolPath = byId('symbol-path').value; if (changed && state.selected) await attach(state.selected); byId('settings-dialog').close(); } catch (error) { byId('settings-error').textContent = String(error); byId('settings-error').hidden = false; } }); });

icons();
controls();
task(async () => { try { const runtime = await request({ op: 'runtime' }); byId('privilege-status').textContent = runtime.elevated ? 'Administrator' : 'Standard user'; byId('app-version').textContent = `v${runtime.version} ${runtime.arch === 'x86' ? 'x86' : 'x64'}`; await loadProcesses(); } catch (error) { byId('process-status').textContent = 'Disconnected'; throw new Error(`Native connection unavailable: ${error}`); } });