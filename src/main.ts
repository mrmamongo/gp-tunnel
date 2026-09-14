import './styles.css';
import { invoke } from '@tauri-apps/api/core';
import { listen, type UnlistenFn } from '@tauri-apps/api/event';

type ConnectionState = 'idle' | 'connecting' | 'connected' | 'disconnecting' | 'error';
type VmState = 'stopped' | 'starting' | 'running' | 'stopping' | 'error';
type VmBootMode = 'disk' | 'iso';
type LogLevel = 'info' | 'success' | 'warn' | 'error';
type PromptKind = 'username' | 'password' | 'mfa' | 'text';
type SocksState = 'disabled' | 'stopped' | 'starting' | 'listening' | 'stopping' | 'error';

interface ConnectionSettings {
  serverHost: string;
  sshPort: number | null;
  sshUser: string;
  identityFile: string;
  knownHostsFile?: string;
  portal: string;
  vm: VmSettings;
  socks: SocksSettings;
  /** Flat aliases are sent to the Tauri command as part of its current API. */
  socksEnabled?: boolean;
  socksPort?: number;
}

interface VmSettings { bootMode: VmBootMode; qemuExe: string; diskImage: string; isoImage: string; memoryMb: number | null; cpus: number | null; sshForwardPort: number | null; autoStartVm: boolean; }
interface SocksSettings { enabled: boolean; port: number; }

interface StatusPayload {
  state: ConnectionState;
  message?: string;
  serverHost?: string;
  portal?: string;
  connectedAt?: string | null;
  socks?: SocksStatusPayload;
}

interface LogPayload { level?: LogLevel; message: string; timestamp?: string; }
interface SocksStatusPayload { state?: string; host?: string; port?: number; endpoint?: string; message?: string; error?: string; }
interface PromptPayload {
  requestId: string;
  fields?: Array<{ kind: PromptKind; label?: string; placeholder?: string; required?: boolean }>;
  kind?: PromptKind;
  message?: string;
  step?: number;
  totalSteps?: number;
}

interface VmStatusPayload { state: VmState; pid?: number; sshForwardPort?: number; message?: string; detail?: string; error?: string; }
interface SavedCredential { username: string; password: string; }

const STORAGE_KEY = 'gp-relay.connection-settings.v1';
const COMMANDS = { connect: 'vpn_connect', disconnect: 'vpn_disconnect', status: 'vpn_status', submitPrompt: 'vpn_submit_prompt', cancel: 'vpn_cancel_prompt', currentPrompt: 'vpn_current_prompt', vmStatus: 'vm_status', vmDiscover: 'vm_discover', vmStart: 'vm_start', vmStop: 'vm_stop', socksStatus: 'socks_status', credentialSave: 'credential_save', credentialLoad: 'credential_load', credentialDelete: 'credential_delete' } as const;
const EVENTS = { status: 'vpn://status', log: 'vpn://log', prompt: 'vpn://prompt', vmStatus: 'vm://status', socksStatus: 'socks://status' } as const;

const $ = <T extends HTMLElement>(id: string) => document.getElementById(id) as T;
const elements = {
  shell: $('app-shell'), tabConnection: $('tab-connection') as HTMLButtonElement, tabSettings: $('tab-settings') as HTMLButtonElement,
  headerState: $('header-state'), headerLabel: $('header-state-label'), orb: $('connection-orb'),
  statusTitle: $('status-title'), statusSubtitle: $('status-subtitle'), connect: $('connect-button') as HTMLButtonElement,
  settingsForm: $('settings-form') as HTMLFormElement, serverHost: $('server-host') as HTMLInputElement,
  sshPort: $('ssh-port') as HTMLInputElement, sshUser: $('ssh-user') as HTMLInputElement, identityFile: $('identity-file') as HTMLInputElement, portal: $('portal') as HTMLInputElement,
  socksForm: $('socks-form') as HTMLFormElement, socksEnabled: $('socks-enabled') as HTMLInputElement, socksPort: $('socks-port') as HTMLInputElement,
  socksLivePill: $('socks-live-pill'), socksEndpointRow: $('socks-endpoint-row'), socksEndpoint: $('socks-endpoint'), detailSocks: $('detail-socks'),
  saveState: $('save-state'), promptPanel: $('prompt-panel'), promptTitle: $('prompt-title'), promptDescription: $('prompt-description'),
  promptStep: $('prompt-step'), promptForm: $('prompt-form') as HTMLFormElement, promptFields: $('prompt-fields'), promptSubmit: $('prompt-submit') as HTMLButtonElement,
  promptCancel: $('prompt-cancel') as HTMLButtonElement, rememberCredentials: $('remember-credentials') as HTMLInputElement, log: $('log'), logEmpty: $('log-empty'), clearLog: $('clear-log') as HTMLButtonElement,
  livePill: $('live-pill'), detailState: $('detail-state'), detailServer: $('detail-server'), detailPortal: $('detail-portal'), detailSince: $('detail-since'), detailVm: $('detail-vm'), detailSsh: $('detail-ssh'),
  sshCommand: $('ssh-command'), sshForwardSummary: $('ssh-forward-summary'), copySshCommand: $('copy-ssh-command') as HTMLButtonElement,
  vmForm: $('vm-form') as HTMLFormElement, bootMode: $('boot-mode') as HTMLSelectElement, qemuExe: $('qemu-exe') as HTMLInputElement,
  diskImage: $('disk-image') as HTMLInputElement, diskImageRow: $('disk-image-row'), isoImage: $('iso-image') as HTMLInputElement,
  isoImageRow: $('iso-image-row'), isoWarning: $('vm-iso-warning'),
  memoryMb: $('memory-mb') as HTMLInputElement, cpus: $('cpus') as HTMLInputElement, sshForwardPort: $('ssh-forward-port') as HTMLInputElement,
  autoStartVm: $('auto-start-vm') as HTMLInputElement, vmStart: $('vm-start-button') as HTMLButtonElement, vmStop: $('vm-stop-button') as HTMLButtonElement,
  vmLivePill: $('vm-live-pill'), vmStatusRow: document.querySelector('.vm-status-row') as HTMLElement, vmStatusLabel: $('vm-status-label'), vmStatusDetail: $('vm-status-detail'),
};

let state: ConnectionState = 'idle';
let vmState: VmState = 'stopped';
let socksState: SocksState = 'disabled';
let activePrompt: PromptPayload | null = null;
let connectedAt: string | null = null;
let unlisteners: UnlistenFn[] = [];
let vmPid: number | null = null;
let promptPollTimer: number | null = null;
let statusPollTimer: number | null = null;
let savedCredential: SavedCredential | null = null;
let currentGpUsername = '';
let currentGpPassword = '';
let connectionOrchestrationActive = false;

type AppTab = 'connection' | 'settings';

function setActiveTab(tab: AppTab) {
  elements.shell.dataset.tab = tab;
  elements.tabConnection.classList.toggle('is-active', tab === 'connection');
  elements.tabSettings.classList.toggle('is-active', tab === 'settings');
  elements.tabConnection.setAttribute('aria-selected', String(tab === 'connection'));
  elements.tabSettings.setAttribute('aria-selected', String(tab === 'settings'));
}

const stateLabels: Record<ConnectionState, string> = { idle: 'Не подключён', connecting: 'Подключение…', connected: 'Подключён', disconnecting: 'Отключение…', error: 'Ошибка' };
const stateTitles: Record<ConnectionState, string> = { idle: 'Готов к подключению', connecting: 'Устанавливаем туннель', connected: 'Туннель активен', disconnecting: 'Закрываем туннель', error: 'Не удалось подключиться' };
const vmStateLabels: Record<VmState, string> = { stopped: 'Выключена', starting: 'Запускается…', running: 'Работает', stopping: 'Останавливается…', error: 'Ошибка VM' };
const socksStateLabels: Record<SocksState, string> = { disabled: 'Выключен', stopped: 'Остановлен', starting: 'Запускается…', listening: 'Слушает', stopping: 'Останавливается…', error: 'Ошибка прокси' };

function readSettings(): ConnectionSettings {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (raw) {
      const saved = JSON.parse(raw) as Partial<ConnectionSettings>;
      const vm = { ...defaultVmSettings(), ...(saved.vm ?? {}) };
      const socks = { ...defaultSocksSettings(), ...(saved.socks ?? {}) };
      const settings = { serverHost: '127.0.0.1', sshPort: 2222, sshUser: 'vpn', identityFile: defaultIdentityFile(), portal: 'gp.domru.ru', ...saved, vm, socks };
      settings.identityFile = migrateLegacyProjectPath(settings.identityFile);
      settings.vm.qemuExe = migrateLegacyProjectPath(settings.vm.qemuExe);
      settings.vm.diskImage = migrateLegacyProjectPath(settings.vm.diskImage);
      settings.vm.isoImage = migrateLegacyProjectPath(settings.vm.isoImage);
      if (settings.knownHostsFile) settings.knownHostsFile = migrateLegacyProjectPath(settings.knownHostsFile);
      if (!settings.serverHost?.trim()) settings.serverHost = '127.0.0.1';
      if (!settings.sshPort) settings.sshPort = 2222;
      if (!settings.sshUser?.trim()) settings.sshUser = 'vpn';
      if (!settings.identityFile?.trim()) settings.identityFile = defaultIdentityFile();
      if (!settings.portal?.trim()) settings.portal = 'gp.domru.ru';
      if (!settings.vm.diskImage?.trim()) settings.vm.diskImage = defaultVmSettings().diskImage;
      if (!Number.isInteger(settings.socks.port) || settings.socks.port < 1 || settings.socks.port > 65535) settings.socks.port = 1081;
      return settings;
    }
  } catch { /* localStorage may be disabled in a WebView */ }
  return { serverHost: '127.0.0.1', sshPort: 2222, sshUser: 'vpn', identityFile: defaultIdentityFile(), portal: 'gp.domru.ru', vm: defaultVmSettings(), socks: defaultSocksSettings() };
}

function defaultIdentityFile(): string {
  return 'vm\\ssh\\gp-relay_ed25519';
}

function defaultKnownHostsFile(): string {
  return 'vm\\ssh\\known_hosts';
}

function migrateLegacyProjectPath(value: string): string {
  const legacyRoot = 'C:\\Work\\globalprotect-remote-gui\\';
  return value.toLowerCase().startsWith(legacyRoot.toLowerCase()) ? value.slice(legacyRoot.length) : value;
}

function defaultVmSettings(): VmSettings {
  return {
    bootMode: 'disk',
    qemuExe: 'tools\\qemu\\qemu-system-x86_64.exe',
    diskImage: 'vm\\ubuntu-gp.qcow2',
    isoImage: '',
    memoryMb: 2048,
    cpus: 2,
    sshForwardPort: 2222,
    autoStartVm: true,
  };
}

function defaultSocksSettings(): SocksSettings {
  return { enabled: true, port: 1081 };
}

function currentSettings(): ConnectionSettings {
  const port = Number.parseInt(elements.sshPort.value, 10);
  const socksPort = Number.parseInt(elements.socksPort.value, 10);
  const numberOrNull = (input: HTMLInputElement) => { const value = Number.parseInt(input.value, 10); return Number.isFinite(value) && value > 0 ? value : null; };
  const normalizedSocksPort = Number.isFinite(socksPort) && socksPort > 0 ? socksPort : 1081;
  return { serverHost: elements.serverHost.value.trim(), sshPort: Number.isFinite(port) && port > 0 ? port : null, sshUser: elements.sshUser.value.trim(), identityFile: elements.identityFile.value.trim(), portal: elements.portal.value.trim(), socks: { enabled: elements.socksEnabled.checked, port: normalizedSocksPort }, socksEnabled: elements.socksEnabled.checked, socksPort: normalizedSocksPort, vm: { bootMode: elements.bootMode.value as VmBootMode, qemuExe: elements.qemuExe.value.trim(), diskImage: elements.diskImage.value.trim(), isoImage: elements.isoImage.value.trim(), memoryMb: numberOrNull(elements.memoryMb), cpus: numberOrNull(elements.cpus), sshForwardPort: numberOrNull(elements.sshForwardPort), autoStartVm: elements.autoStartVm.checked } };
}

function saveSettings() {
  try { localStorage.setItem(STORAGE_KEY, JSON.stringify(currentSettings())); elements.saveState.textContent = 'Сохранено локально'; } catch { elements.saveState.textContent = 'Только на этот запуск'; }
}

function applySettings(settings: ConnectionSettings) {
  elements.serverHost.value = settings.serverHost;
  elements.sshPort.value = settings.sshPort?.toString() ?? '';
  elements.sshUser.value = settings.sshUser;
  elements.identityFile.value = settings.identityFile;
  elements.portal.value = settings.portal;
  elements.socksEnabled.checked = settings.socks.enabled;
  elements.socksPort.value = settings.socks.port.toString();
  elements.bootMode.value = settings.vm.bootMode;
  elements.qemuExe.value = settings.vm.qemuExe;
  elements.diskImage.value = settings.vm.diskImage;
  elements.isoImage.value = settings.vm.isoImage;
  elements.memoryMb.value = settings.vm.memoryMb?.toString() ?? '';
  elements.cpus.value = settings.vm.cpus?.toString() ?? '';
  elements.sshForwardPort.value = settings.vm.sshForwardPort?.toString() ?? '';
  elements.autoStartVm.checked = settings.vm.autoStartVm;
}

function updateBootModeUi() {
  const isoMode = elements.bootMode.value === 'iso';
  elements.diskImageRow.classList.toggle('is-hidden', isoMode);
  elements.diskImageRow.setAttribute('aria-hidden', String(isoMode));
  elements.isoImageRow.classList.toggle('is-hidden', !isoMode);
  elements.isoImageRow.setAttribute('aria-hidden', String(!isoMode));
  elements.isoWarning.classList.toggle('is-hidden', !isoMode);
  elements.diskImage.required = !isoMode;
  elements.isoImage.required = isoMode;
  elements.autoStartVm.disabled = isoMode;
  if (isoMode) elements.autoStartVm.checked = false;
}

function setState(next: ConnectionState, message?: string) {
  state = next;
  elements.headerState.dataset.state = next;
  elements.orb.dataset.state = next;
  elements.livePill.dataset.state = next;
  elements.livePill.textContent = next.toUpperCase();
  elements.headerLabel.textContent = stateLabels[next];
  elements.statusTitle.textContent = stateTitles[next];
  elements.statusSubtitle.textContent = message ?? (next === 'connected' ? 'Трафик проходит через удалённый relay.' : next === 'error' ? 'Проверьте параметры и журнал сеанса.' : 'Укажите сервер и портал, чтобы начать.');
  elements.detailState.textContent = stateLabels[next];
  elements.connect.disabled = next === 'connecting' || next === 'disconnecting';
  elements.connect.innerHTML = next === 'connected' ? '<span class="button-icon" aria-hidden="true">×</span> Отключить' : '<span class="button-icon" aria-hidden="true">↗</span> Подключить';
  if (next === 'connected') connectedAt = connectedAt ?? new Date().toISOString();
  if (next === 'idle' || next === 'error') connectedAt = null;
  elements.detailSince.textContent = connectedAt ? formatDate(connectedAt) : '—';
}

function sshCommand(): string {
  const port = Number.parseInt(elements.sshForwardPort.value, 10) || 2222;
  const user = elements.sshUser.value.trim() || 'vpn';
  const identity = elements.identityFile.value.trim();
  return `ssh -p ${port}${identity ? ` -i "${identity}"` : ''} ${user}@127.0.0.1`;
}

function updateSshAccess() {
  const port = Number.parseInt(elements.sshForwardPort.value, 10) || 2222;
  elements.sshCommand.textContent = sshCommand();
  elements.sshForwardSummary.textContent = `127.0.0.1:${port} → VM:22`;
}

function setVmState(next: VmState, message?: string, detail?: string, pid?: number, sshPort?: number) {
  vmState = next; elements.vmLivePill.dataset.state = next; elements.vmLivePill.textContent = next.toUpperCase(); elements.vmStatusRow.dataset.state = next;
  if (pid !== undefined) vmPid = pid;
  if (next === 'stopped') vmPid = null;
  elements.vmStatusLabel.textContent = message ?? vmStateLabels[next]; elements.vmStatusDetail.textContent = detail ?? '';
  const port = sshPort ?? (Number.parseInt(elements.sshForwardPort.value, 10) || 2222);
  elements.detailVm.textContent = next === 'running' ? `Работает${vmPid ? ` · PID ${vmPid}` : ''}` : next === 'starting' ? `Запускается${vmPid ? ` · PID ${vmPid}` : ''}` : vmStateLabels[next];
  elements.detailSsh.textContent = next === 'running' ? `Доступен · 127.0.0.1:${port}` : next === 'starting' ? (message ?? 'Ожидаем Ubuntu') : next === 'error' ? 'Ошибка подключения' : 'Недоступен';
  elements.vmStart.disabled = next === 'starting' || next === 'running' || next === 'stopping'; elements.vmStop.disabled = next === 'stopped' || next === 'stopping' || next === 'starting';
}

function socksEndpoint(port = Number.parseInt(elements.socksPort.value, 10)): string {
  return `socks5h://127.0.0.1:${Number.isInteger(port) && port > 0 ? port : 1081}`;
}

function updateSocksUi() {
  const enabled = elements.socksEnabled.checked;
  elements.socksPort.disabled = !enabled;
  elements.socksPort.required = enabled;
  elements.socksEndpointRow.classList.toggle('is-muted', !enabled);
  elements.socksEndpoint.textContent = socksEndpoint();
  if (!enabled && socksState !== 'listening') setSocksStatus({ state: 'disabled' });
}

function setSocksStatus(payload: SocksStatusPayload = {}) {
  const rawState = payload.state?.toLowerCase();
  const next: SocksState = !elements.socksEnabled.checked || rawState === 'disabled'
    ? 'disabled'
    : rawState === 'listening' || rawState === 'running' || rawState === 'connected'
      ? 'listening'
      : rawState === 'starting' || rawState === 'connecting'
        ? 'starting'
        : rawState === 'stopping' || rawState === 'disconnecting'
          ? 'stopping'
          : rawState === 'error' || rawState === 'failed'
            ? 'error'
            : 'stopped';
  socksState = next;
  elements.socksLivePill.dataset.state = next;
  elements.socksLivePill.textContent = next === 'listening' ? 'LISTENING' : next.toUpperCase();
  const parsedPort = Number.parseInt(elements.socksPort.value, 10);
  const port = payload.port ?? (Number.isInteger(parsedPort) && parsedPort > 0 ? parsedPort : 1081);
  const endpoint = payload.endpoint || socksEndpoint(port);
  elements.socksEndpoint.textContent = endpoint;
  elements.detailSocks.textContent = next === 'listening' ? endpoint : socksStateLabels[next];
  if (payload.message) elements.socksEndpointRow.dataset.message = payload.message;
}

function formatDate(value: string): string { const date = new Date(value); return Number.isNaN(date.valueOf()) ? value : date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }); }

function appendLog(payload: LogPayload | string) {
  const entry: LogPayload = typeof payload === 'string' ? { message: payload } : payload;
  elements.logEmpty?.remove();
  const row = document.createElement('div'); row.className = 'log-line'; row.dataset.level = entry.level ?? 'info';
  const time = entry.timestamp ? formatDate(entry.timestamp) : new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  row.innerHTML = `<span class="log-time">${escapeHtml(time)}</span><span class="log-level">${(entry.level ?? 'info').toUpperCase()}</span><span class="log-message">${escapeHtml(entry.message)}</span>`;
  elements.log.append(row); elements.log.scrollTop = elements.log.scrollHeight;
}

function escapeHtml(value: string): string { const node = document.createElement('span'); node.textContent = value; return node.innerHTML; }

function showPrompt(payload: PromptPayload) {
  if (activePrompt?.requestId === payload.requestId && elements.promptFields.querySelector('input')) return;
  elements.promptPanel.classList.remove('is-hidden');
  const fields = payload.fields?.length ? payload.fields : [{ kind: payload.kind ?? 'text', label: payload.message ?? 'Ответ' }];
  elements.promptFields.innerHTML = fields.map((field, index) => {
    const id = `prompt-${index}`;
    const type = field.kind === 'password' || field.kind === 'mfa' ? 'password' : 'text';
    const autocomplete = field.kind === 'username' ? 'username' : 'off';
    return `<label class="prompt-field" for="${id}"><span>${escapeHtml(field.label ?? promptLabel(field.kind))}</span><input id="${id}" name="${field.kind}" type="${type}" placeholder="${escapeHtml(field.placeholder ?? promptPlaceholder(field.kind))}" autocomplete="${autocomplete}" ${field.required === false ? '' : 'required'} /></label>`;
  }).join('');
  elements.promptTitle.textContent = payload.message ?? (fields.length > 1 ? 'Введите данные для входа' : promptLabel(fields[0].kind));
  elements.promptDescription.textContent = 'Данные передаются в текущую SSH-сессию и удаляются после ответа.';
  elements.promptStep.textContent = payload.step && payload.totalSteps ? `${payload.step} / ${payload.totalSteps}` : 'INTERACTIVE';
  for (const input of elements.promptFields.querySelectorAll<HTMLInputElement>('input')) {
    if (input.name === 'username') input.value = savedCredential?.username || currentGpUsername;
    if (input.name === 'password') input.value = savedCredential?.password || currentGpPassword;
  }
  elements.rememberCredentials.checked = savedCredential !== null;
  elements.promptSubmit.disabled = false;
  elements.promptCancel.disabled = false;
  activePrompt = payload;
  const firstInput = elements.promptFields.querySelector('input') as HTMLInputElement | null; firstInput?.focus();
}

function promptLabel(kind: PromptKind): string { return ({ username: 'Имя пользователя GlobalProtect', password: 'Пароль GlobalProtect', mfa: 'Одноразовый код', text: 'Ответ сервера' })[kind]; }
function promptPlaceholder(kind: PromptKind): string { return ({ username: 'user', password: '••••••••', mfa: '123456', text: 'Введите ответ' })[kind]; }
function hidePrompt() {
  activePrompt = null;
  elements.promptPanel.classList.add('is-hidden');
  elements.promptTitle.textContent = 'Ожидаю запрос OpenConnect';
  elements.promptDescription.textContent = 'Когда сервер запросит логин, пароль, OTP или challenge, поле появится здесь.';
  elements.promptStep.textContent = 'WAITING';
  elements.promptFields.innerHTML = '<p class="auth-waiting">Сейчас ввод не требуется. Состояние запроса проверяется каждые 500 мс.</p>';
  elements.promptSubmit.disabled = true;
  elements.promptCancel.disabled = true;
}

async function connect() {
  if (connectionOrchestrationActive) return;
  connectionOrchestrationActive = true;
  try { await connectFlow(); }
  finally { connectionOrchestrationActive = false; }
}

async function connectFlow() {
  if (state === 'connected') return disconnect();
  if (!elements.settingsForm.reportValidity()) return;
  if (!elements.socksForm.reportValidity()) return;
  const settings = currentSettings(); saveSettings(); setActiveTab('connection'); setState('connecting');
  if (settings.socks.enabled) {
    setSocksStatus({ state: 'starting', port: settings.socks.port });
    appendLog({ level: 'info', message: `После подключения запущу SOCKS5 на ${socksEndpoint(settings.socks.port)}.` });
  } else {
    setSocksStatus({ state: 'disabled' });
    appendLog({ level: 'info', message: 'Локальный SOCKS5 отключён в настройках.' });
  }
  if (settings.vm.bootMode === 'iso') {
    setState('idle', 'ISO-режим предназначен только для запуска установщика Ubuntu.');
    appendLog({ level: 'warn', message: 'VPN не запускается в ISO-режиме: сначала установите Ubuntu на отдельный диск.' });
    return;
  }
  if (settings.vm.autoStartVm && vmState !== 'running') {
    if (vmState === 'starting') {
      appendLog({ level: 'info', message: 'Relay VM уже запускается — жду готовности Ubuntu SSH.' });
    } else if (vmState === 'stopping') {
      setState('error', 'VM сейчас останавливается. Дождитесь завершения и повторите подключение.');
      return;
    } else {
      appendLog({ level: 'info', message: 'Автозапуск включён — сначала запускаю relay VM.' });
      if (!await startVm()) { setState('error', 'VM не запустилась, VPN не запускался.'); return; }
    }
    if (!await waitForVmRunning()) { setState('error', 'VM не запустилась, VPN не запускался.'); return; }
  }
  const vpnSettings = settings.vm.autoStartVm
    ? { ...settings, serverHost: '127.0.0.1', sshPort: settings.vm.sshForwardPort ?? 2222, knownHostsFile: settings.knownHostsFile || defaultKnownHostsFile() }
    : settings;
  appendLog({ level: 'info', message: `Подключение к ${vpnSettings.serverHost}:${vpnSettings.sshPort ?? 22}…` });
  try { await invoke(COMMANDS.connect, { settings: vpnSettings }); }
  catch (error) { setState('error'); appendLog({ level: 'error', message: error instanceof Error ? error.message : String(error) }); }
}

async function disconnect() {
  setState('disconnecting'); appendLog({ level: 'info', message: 'Запрашиваю отключение…' });
  if (socksState === 'listening' || socksState === 'starting') setSocksStatus({ state: 'stopping' });
  try { await invoke(COMMANDS.disconnect); }
  catch (error) { setState('error'); appendLog({ level: 'error', message: error instanceof Error ? error.message : String(error) }); }
}

async function startVm(): Promise<boolean> {
  if (vmState === 'running') return true;
  if (vmState === 'starting') return true;
  if (vmState === 'stopping') {
    appendLog({ level: 'warn', message: 'VM сейчас останавливается — новый запуск пока невозможен.' });
    return false;
  }
  const settings = currentSettings().vm;
  if (!settings.qemuExe) { appendLog({ level: 'warn', message: 'Укажите QEMU executable.' }); elements.qemuExe.focus(); return false; }
  if (settings.bootMode === 'disk' && !settings.diskImage) { appendLog({ level: 'warn', message: 'Для обычной загрузки укажите disk image.' }); elements.diskImage.focus(); return false; }
  if (settings.bootMode === 'iso' && !settings.isoImage) { appendLog({ level: 'warn', message: 'Для ISO-режима укажите Ubuntu ISO.' }); elements.isoImage.focus(); return false; }
  saveSettings(); setVmState('starting'); appendLog({ level: 'info', message: 'Запускаю relay VM…' });
  try {
    const payload = await invoke<VmStatusPayload>(COMMANDS.vmStart, { settings: { ...settings, sshUser: currentSettings().sshUser, identityFile: currentSettings().identityFile } });
    setVmState(payload.state, payload.message, payload.detail ?? payload.error, payload.pid, payload.sshForwardPort);
    return payload.state === 'starting' || payload.state === 'running';
  } catch (error) { setVmState('error'); appendLog({ level: 'error', message: error instanceof Error ? error.message : String(error) }); return false; }
}

async function waitForVmRunning(timeoutMs = 60_000): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (vmState === 'running') return true;
    try {
      const payload = await invoke<VmStatusPayload>(COMMANDS.vmStatus);
      setVmState(payload.state, payload.message, payload.detail ?? payload.error, payload.pid, payload.sshForwardPort);
      if (payload.state === 'running') return true;
      if (payload.state === 'error' || payload.state === 'stopped') return false;
    } catch { /* retry while QEMU/sshd is starting */ }
    await new Promise((resolve) => window.setTimeout(resolve, 500));
  }
  return false;
}

async function pollRuntimeStatus() {
  try {
    const payload = await invoke<VmStatusPayload>(COMMANDS.vmStatus);
    setVmState(payload.state, payload.message, payload.detail ?? payload.error, payload.pid, payload.sshForwardPort);
  } catch { /* backend may be shutting down */ }
  try {
    const payload = await invoke<StatusPayload>(COMMANDS.status);
    if (payload.serverHost) elements.detailServer.textContent = payload.serverHost;
    if (payload.portal) elements.detailPortal.textContent = payload.portal;
    if (payload.connectedAt) connectedAt = payload.connectedAt;
    if (payload.socks) setSocksStatus(payload.socks);
    if (!connectionOrchestrationActive || payload.state !== 'idle') setState(payload.state, payload.message);
    if (payload.state === 'connected' || payload.state === 'idle' || payload.state === 'error') hidePrompt();
  } catch { /* backend may be shutting down */ }
  try {
    const payload = await invoke<SocksStatusPayload>(COMMANDS.socksStatus);
    setSocksStatus(payload);
  } catch { /* backend may be shutting down */ }
}

async function stopVm() {
  setVmState('stopping'); appendLog({ level: 'info', message: 'Останавливаю relay VM…' });
  try { await invoke(COMMANDS.vmStop); } catch (error) { setVmState('error'); appendLog({ level: 'error', message: error instanceof Error ? error.message : String(error) }); }
}

async function submitPrompt(event: SubmitEvent) {
  event.preventDefault(); if (!activePrompt) return;
  const values = Object.fromEntries(new FormData(elements.promptForm).entries());
  const promptKind = activePrompt.fields?.[0]?.kind ?? activePrompt.kind;
  const response = promptKind ? String(values[promptKind] ?? '') : '';
  elements.promptSubmit.disabled = true;
  try {
    await invoke(COMMANDS.submitPrompt, { requestId: activePrompt.requestId, values });
    if (promptKind === 'username') currentGpUsername = response;
    if (promptKind === 'password') {
      currentGpPassword = response;
      if (elements.rememberCredentials.checked && currentGpUsername) {
        await invoke(COMMANDS.credentialSave, { username: currentGpUsername, password: response });
        savedCredential = { username: currentGpUsername, password: response };
        appendLog({ level: 'success', message: 'Логин и пароль сохранены через Windows DPAPI.' });
      } else if (!elements.rememberCredentials.checked) {
        await invoke(COMMANDS.credentialDelete);
        savedCredential = null;
      }
    }
    hidePrompt(); appendLog({ level: 'info', message: 'Ответ отправлен.' });
  }
  catch (error) { appendLog({ level: 'error', message: error instanceof Error ? error.message : String(error) }); }
  finally { elements.promptSubmit.disabled = false; }
}

async function cancelPrompt() { if (!activePrompt) return; try { await invoke(COMMANDS.cancel, { requestId: activePrompt.requestId }); } catch { /* backend may already have cancelled */ } hidePrompt(); setState('idle', 'Ввод отменён.'); appendLog({ level: 'warn', message: 'Аутентификация отменена.' }); }

async function setupBridge() {
  try {
    unlisteners = await Promise.all([
      listen<StatusPayload>(EVENTS.status, ({ payload }) => { if (payload.connectedAt) connectedAt = payload.connectedAt; setState(payload.state, payload.message); if (payload.serverHost) elements.detailServer.textContent = payload.serverHost; if (payload.portal) elements.detailPortal.textContent = payload.portal; if (payload.socks) setSocksStatus(payload.socks); if (payload.state === 'connected' || payload.state === 'idle' || payload.state === 'error') hidePrompt(); }),
      listen<LogPayload>(EVENTS.log, ({ payload }) => appendLog(payload)),
      listen<PromptPayload>(EVENTS.prompt, ({ payload }) => { setState('connecting', payload.message ?? 'Ожидаем данные аутентификации.'); showPrompt(payload); }),
      listen<VmStatusPayload>(EVENTS.vmStatus, ({ payload }) => { setVmState(payload.state, payload.message, payload.detail ?? payload.error, payload.pid, payload.sshForwardPort); }),
      listen<SocksStatusPayload>(EVENTS.socksStatus, ({ payload }) => { setSocksStatus(payload); const message = payload.message || payload.error; if (message) appendLog({ level: payload.state === 'error' ? 'error' : 'info', message: `SOCKS5: ${message}` }); }),
    ]);
  } catch (error) {
    unlisteners = [];
    appendLog({ level: 'warn', message: `События Tauri недоступны, продолжаю через polling: ${String(error)}` });
  }
  try { const payload = await invoke<StatusPayload>(COMMANDS.status); if (payload) { if (payload.serverHost) elements.detailServer.textContent = payload.serverHost; if (payload.portal) elements.detailPortal.textContent = payload.portal; if (payload.connectedAt) connectedAt = payload.connectedAt; if (payload.socks) setSocksStatus(payload.socks); setState(payload.state, payload.message); } }
  catch { appendLog({ level: 'warn', message: 'Статус relay пока недоступен — можно попробовать подключиться.' }); }
  try {
    const settings = currentSettings();
    const payload = await invoke<VmStatusPayload>(COMMANDS.vmDiscover, { settings: { ...settings.vm, sshUser: settings.sshUser, identityFile: settings.identityFile } });
    if (payload) setVmState(payload.state, payload.message, payload.detail ?? payload.error, payload.pid, payload.sshForwardPort);
  } catch { appendLog({ level: 'warn', message: 'Статус VM пока недоступен.' }); }
  try { const payload = await invoke<SocksStatusPayload>(COMMANDS.socksStatus); if (payload) setSocksStatus(payload); } catch { appendLog({ level: 'warn', message: 'Статус SOCKS5 пока недоступен.' }); }
  try {
    savedCredential = await invoke<SavedCredential | null>(COMMANDS.credentialLoad);
    if (savedCredential) {
      currentGpUsername = savedCredential.username;
      elements.rememberCredentials.checked = true;
    }
  }
  catch (error) { appendLog({ level: 'warn', message: `Не удалось загрузить сохранённые креды: ${String(error)}` }); }
  promptPollTimer = window.setInterval(async () => {
    try {
      const payload = await invoke<PromptPayload | null>(COMMANDS.currentPrompt);
      if (payload && activePrompt?.requestId !== payload.requestId) showPrompt(payload);
    } catch { /* transient backend shutdown */ }
  }, 500);
  statusPollTimer = window.setInterval(() => void pollRuntimeStatus(), 750);
}

applySettings(readSettings());
updateBootModeUi();
updateSocksUi();
updateSshAccess();
setState('idle');
setVmState('stopped');
setSocksStatus({ state: elements.socksEnabled.checked ? 'stopped' : 'disabled' });
hidePrompt();
elements.detailServer.textContent = elements.serverHost.value || '—'; elements.detailPortal.textContent = elements.portal.value || '—';
elements.connect.addEventListener('click', () => void connect());
elements.tabConnection.addEventListener('click', () => setActiveTab('connection'));
elements.tabSettings.addEventListener('click', () => setActiveTab('settings'));
elements.vmStart.addEventListener('click', () => void startVm());
elements.vmStop.addEventListener('click', () => void stopVm());
elements.promptForm.addEventListener('submit', (event) => void submitPrompt(event));
elements.promptCancel.addEventListener('click', () => void cancelPrompt());
elements.clearLog.addEventListener('click', () => { elements.log.innerHTML = '<div class="log-empty" id="log-empty">Здесь появятся события подключения.</div>'; });
elements.settingsForm.addEventListener('input', () => { updateSshAccess(); saveSettings(); elements.detailServer.textContent = elements.serverHost.value || '—'; elements.detailPortal.textContent = elements.portal.value || '—'; });
elements.socksForm.addEventListener('input', () => { updateSocksUi(); saveSettings(); if (state === 'idle' || state === 'error') setSocksStatus({ state: elements.socksEnabled.checked ? 'stopped' : 'disabled' }); });
elements.vmForm.addEventListener('input', () => { updateBootModeUi(); updateSshAccess(); saveSettings(); });
elements.copySshCommand.addEventListener('click', async () => {
  try {
    await navigator.clipboard.writeText(sshCommand());
    elements.copySshCommand.textContent = 'Скопировано';
    window.setTimeout(() => { elements.copySshCommand.textContent = 'Копировать'; }, 1400);
  } catch (error) {
    appendLog({ level: 'warn', message: `Не удалось скопировать SSH-команду: ${String(error)}` });
  }
});
window.addEventListener('beforeunload', () => {
  unlisteners.forEach((unlisten) => unlisten());
  if (promptPollTimer !== null) window.clearInterval(promptPollTimer);
  if (statusPollTimer !== null) window.clearInterval(statusPollTimer);
});
void setupBridge();
