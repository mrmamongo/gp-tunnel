import './styles.css';
import { invoke } from '@tauri-apps/api/core';
import { listen, type UnlistenFn } from '@tauri-apps/api/event';

type ConnectionState = 'idle' | 'connecting' | 'connected' | 'disconnecting' | 'error';
type LogLevel = 'info' | 'success' | 'warn' | 'error';
type PromptKind = 'username' | 'password' | 'mfa' | 'text';
type SocksState = 'stopped' | 'starting' | 'listening' | 'stopping' | 'error';

/** Настройки подключения: openconnect работает в контейнере gp-relay, поэтому
 *  от пользователя нужен только портал GlobalProtect. */
interface ConnectionSettings { portal: string; }

interface StatusPayload {
  state: ConnectionState;
  message?: string;
  portal?: string;
  connectedAt?: string | null;
}

interface LogPayload { level?: LogLevel; message: string; timestamp?: string; }
interface SocksStatusPayload { state?: string; port?: number; endpoint?: string; message?: string; error?: string; }
interface PromptPayload {
  requestId: string;
  fields?: Array<{ kind: PromptKind; label?: string; placeholder?: string; required?: boolean }>;
  kind?: PromptKind;
  message?: string;
  step?: number;
  totalSteps?: number;
}

interface SavedCredential { username: string; password: string; }

const STORAGE_KEY = 'gp-relay.connection-settings.v1';
const DEFAULT_PORTAL = 'gp.domru.ru';
/** Relay живёт в контейнере: имя образа и порты фиксированы docker-путём. */
const DOCKER_CONTAINER = 'gp-relay';
const DOCKER_IMAGE = 'ghcr.io/mrmamongo/gp-relay:latest';
const DOCKER_SOCKS_PORT = 1080;

const COMMANDS = { connect: 'vpn_connect', disconnect: 'vpn_disconnect', status: 'vpn_status', submitPrompt: 'vpn_submit_prompt', cancel: 'vpn_cancel_prompt', currentPrompt: 'vpn_current_prompt', socksStatus: 'socks_status', credentialSave: 'credential_save', credentialLoad: 'credential_load', credentialDelete: 'credential_delete', dockerExec: 'docker_exec' } as const;
const EVENTS = { status: 'vpn://status', log: 'vpn://log', prompt: 'vpn://prompt' } as const;

const $ = <T extends HTMLElement>(id: string) => document.getElementById(id) as T;
const elements = {
  shell: $('app-shell'), tabConnection: $('tab-connection') as HTMLButtonElement, tabSettings: $('tab-settings') as HTMLButtonElement,
  headerState: $('header-state'), headerLabel: $('header-state-label'), orb: $('connection-orb'),
  statusTitle: $('status-title'), statusSubtitle: $('status-subtitle'), connect: $('connect-button') as HTMLButtonElement,
  settingsForm: $('settings-form') as HTMLFormElement, portal: $('portal') as HTMLInputElement, saveState: $('save-state'),
  socksLivePill: $('socks-live-pill'), socksEndpointRow: $('socks-endpoint-row'), socksEndpoint: $('socks-endpoint'), detailSocks: $('detail-socks'),
  promptPanel: $('prompt-panel'), promptTitle: $('prompt-title'), promptDescription: $('prompt-description'), promptStep: $('prompt-step'),
  promptForm: $('prompt-form') as HTMLFormElement, promptFields: $('prompt-fields'), promptSubmit: $('prompt-submit') as HTMLButtonElement,
  promptCancel: $('prompt-cancel') as HTMLButtonElement, rememberCredentials: $('remember-credentials') as HTMLInputElement,
  log: $('log'), logEmpty: $('log-empty'), clearLog: $('clear-log') as HTMLButtonElement,
  livePill: $('live-pill'), detailState: $('detail-state'), detailPortal: $('detail-portal'), detailSince: $('detail-since'),
};

let state: ConnectionState = 'idle';
let socksState: SocksState = 'stopped';
let activePrompt: PromptPayload | null = null;
let connectedAt: string | null = null;
let unlisteners: UnlistenFn[] = [];
let promptPollTimer: number | null = null;
let statusPollTimer: number | null = null;
let socksPollTimer: number | null = null;
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
const socksStateLabels: Record<SocksState, string> = { stopped: 'Остановлен', starting: 'Запускается…', listening: 'Слушает', stopping: 'Останавливается…', error: 'Ошибка прокси' };

function readSettings(): ConnectionSettings {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (raw) {
      const saved = JSON.parse(raw) as Partial<ConnectionSettings>;
      return { portal: saved.portal?.trim() || DEFAULT_PORTAL };
    }
  } catch { /* localStorage may be disabled in a WebView */ }
  return { portal: DEFAULT_PORTAL };
}

function currentSettings(): ConnectionSettings {
  return { portal: elements.portal.value.trim() || DEFAULT_PORTAL };
}

function saveSettings() {
  try { localStorage.setItem(STORAGE_KEY, JSON.stringify(currentSettings())); elements.saveState.textContent = 'Сохранено локально'; } catch { elements.saveState.textContent = 'Только на этот запуск'; }
}

function applySettings(settings: ConnectionSettings) {
  elements.portal.value = settings.portal;
}

function setState(next: ConnectionState, message?: string) {
  state = next;
  elements.headerState.dataset.state = next;
  elements.orb.dataset.state = next;
  elements.livePill.dataset.state = next;
  elements.livePill.textContent = next.toUpperCase();
  elements.headerLabel.textContent = stateLabels[next];
  elements.statusTitle.textContent = stateTitles[next];
  elements.statusSubtitle.textContent = message ?? (next === 'connected' ? 'Трафик проходит через контейнер gp-relay.' : next === 'error' ? 'Проверьте параметры и журнал сеанса.' : 'Укажите портал GlobalProtect, чтобы начать.');
  elements.detailState.textContent = stateLabels[next];
  elements.connect.disabled = next === 'connecting' || next === 'disconnecting';
  elements.connect.innerHTML = next === 'connected' ? '<span class="button-icon" aria-hidden="true">×</span> Отключить' : '<span class="button-icon" aria-hidden="true">↗</span> Подключить';
  if (next === 'connected') connectedAt = connectedAt ?? new Date().toISOString();
  if (next === 'idle' || next === 'error') connectedAt = null;
  elements.detailSince.textContent = connectedAt ? formatDate(connectedAt) : '—';
}

function socksEndpoint(port = DOCKER_SOCKS_PORT): string {
  return `socks5h://127.0.0.1:${port}`;
}

function setSocksStatus(payload: SocksStatusPayload = {}) {
  const rawState = payload.state?.toLowerCase();
  const next: SocksState = rawState === 'listening' || rawState === 'running' || rawState === 'connected'
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
  const port = payload.port && payload.port > 0 ? payload.port : DOCKER_SOCKS_PORT;
  const endpoint = payload.endpoint || socksEndpoint(port);
  elements.socksEndpoint.textContent = endpoint;
  elements.detailSocks.textContent = next === 'listening' ? `${endpoint} · dante в контейнере` : socksStateLabels[next];
  const note = payload.message || payload.error;
  if (note) elements.socksEndpointRow.dataset.message = note;
  else delete elements.socksEndpointRow.dataset.message;
}

/** SOCKS5 поднимает dante внутри контейнера gp-relay — GUI только отражает статус. */
async function refreshSocksStatus() {
  try {
    const payload = await invoke<SocksStatusPayload>(COMMANDS.socksStatus);
    setSocksStatus(payload);
  } catch {
    setSocksStatus({ state: 'stopped' });
  }
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
  elements.promptDescription.textContent = 'Данные передаются в openconnect внутри контейнера и удаляются после ответа.';
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

// ——— Docker-путь: контейнер gp-relay, openconnect внутри него ———
// GUI поднимает контейнер (если он ещё не работает) и ведёт сессию через
// docker exec. SOCKS5 даёт dante в контейнере, ssh.exe/QEMU не участвуют.
async function dockerContainerRunning(): Promise<boolean> {
  try { const out = await invoke<string>(COMMANDS.dockerExec, { args: ['inspect', '-f', '{{.State.Running}}', DOCKER_CONTAINER] }); return out.trim() === 'true'; }
  catch { return false; }
}

async function dockerEnsureContainer(): Promise<boolean> {
  if (await dockerContainerRunning()) { appendLog({ level: 'info', message: `Контейнер ${DOCKER_CONTAINER} уже работает.` }); return true; }
  appendLog({ level: 'info', message: `Запускаю контейнер ${DOCKER_IMAGE}…` });
  try {
    await invoke(COMMANDS.dockerExec, { args: ['run', '-d', '--name', DOCKER_CONTAINER, '--cap-add', 'NET_ADMIN', '--device', '/dev/net/tun', '-p', `${DOCKER_SOCKS_PORT}:1080`, '--restart', 'unless-stopped', DOCKER_IMAGE] });
    appendLog({ level: 'success', message: `Контейнер gp-relay запущен (SOCKS5 :${DOCKER_SOCKS_PORT}).` });
    return true;
  } catch (error) { appendLog({ level: 'error', message: `Не удалось запустить контейнер: ${error instanceof Error ? error.message : String(error)}` }); return false; }
}

async function connectFlow() {
  if (state === 'connected') return disconnect();
  if (!elements.settingsForm.reportValidity()) return;
  const settings = currentSettings(); saveSettings(); setActiveTab('connection'); setState('connecting');
  if (!await dockerEnsureContainer()) { setState('error', 'Контейнер gp-relay не запустился, VPN не запускался.'); return; }
  appendLog({ level: 'info', message: `Подключаюсь к порталу ${settings.portal} через контейнер ${DOCKER_CONTAINER}…` });
  appendLog({ level: 'info', message: `openconnect запускается прямо в контейнере (docker exec + PTY). SOCKS5 слушает ${socksEndpoint()} — это dante внутри контейнера, отдельно поднимать не нужно.` });
  try {
    await invoke(COMMANDS.connect, { settings });
    // dante уже внутри контейнера: обновляем индикатор прокси сразу после старта.
    void refreshSocksStatus();
  } catch (error) { setState('error'); appendLog({ level: 'error', message: error instanceof Error ? error.message : String(error) }); }
}

async function disconnect() {
  setState('disconnecting'); appendLog({ level: 'info', message: 'Запрашиваю отключение…' });
  try { await invoke(COMMANDS.disconnect); }
  catch (error) { setState('error'); appendLog({ level: 'error', message: error instanceof Error ? error.message : String(error) }); }
}

async function pollRuntimeStatus() {
  try {
    const payload = await invoke<StatusPayload>(COMMANDS.status);
    if (payload.portal) elements.detailPortal.textContent = payload.portal;
    if (payload.connectedAt) connectedAt = payload.connectedAt;
    if (!connectionOrchestrationActive || payload.state !== 'idle') setState(payload.state, payload.message);
    if (payload.state === 'connected' || payload.state === 'idle' || payload.state === 'error') hidePrompt();
  } catch { /* backend may be shutting down */ }
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
      listen<StatusPayload>(EVENTS.status, ({ payload }) => {
        if (payload.connectedAt) connectedAt = payload.connectedAt;
        setState(payload.state, payload.message);
        if (payload.portal) elements.detailPortal.textContent = payload.portal;
        if (payload.state === 'connected' || payload.state === 'idle' || payload.state === 'error') hidePrompt();
        void refreshSocksStatus();
      }),
      listen<LogPayload>(EVENTS.log, ({ payload }) => appendLog(payload)),
      listen<PromptPayload>(EVENTS.prompt, ({ payload }) => { setState('connecting', payload.message ?? 'Ожидаем данные аутентификации.'); showPrompt(payload); }),
    ]);
  } catch (error) {
    unlisteners = [];
    appendLog({ level: 'warn', message: `События Tauri недоступны, продолжаю через polling: ${String(error)}` });
  }
  try { const payload = await invoke<StatusPayload>(COMMANDS.status); if (payload) { if (payload.portal) elements.detailPortal.textContent = payload.portal; if (payload.connectedAt) connectedAt = payload.connectedAt; setState(payload.state, payload.message); } }
  catch { appendLog({ level: 'warn', message: 'Статус relay пока недоступен — можно попробовать подключиться.' }); }
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
  socksPollTimer = window.setInterval(() => void refreshSocksStatus(), 3_000);
  void refreshSocksStatus();
}

applySettings(readSettings());
setState('idle');
setSocksStatus({ state: 'stopped' });
hidePrompt();
elements.detailPortal.textContent = elements.portal.value || '—';
elements.connect.addEventListener('click', () => void connect());
elements.tabConnection.addEventListener('click', () => setActiveTab('connection'));
elements.tabSettings.addEventListener('click', () => setActiveTab('settings'));
elements.promptForm.addEventListener('submit', (event) => void submitPrompt(event));
elements.promptCancel.addEventListener('click', () => void cancelPrompt());
elements.clearLog.addEventListener('click', () => { elements.log.innerHTML = '<div class="log-empty" id="log-empty">Здесь появятся события подключения.</div>'; });
elements.settingsForm.addEventListener('input', () => { saveSettings(); elements.detailPortal.textContent = elements.portal.value || '—'; });
try { localStorage.removeItem('gp-relay.backend'); } catch { /* ок */ }
window.addEventListener('beforeunload', () => {
  unlisteners.forEach((unlisten) => unlisten());
  if (promptPollTimer !== null) window.clearInterval(promptPollTimer);
  if (statusPollTimer !== null) window.clearInterval(statusPollTimer);
  if (socksPollTimer !== null) window.clearInterval(socksPollTimer);
});
void setupBridge();
