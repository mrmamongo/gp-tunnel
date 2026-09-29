import './styles.css';
import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import { version } from '../package.json';

type PromptKind = 'username' | 'password' | 'mfa' | 'challenge' | 'gateway' | 'text';
interface Prompt { requestId: string; kind: PromptKind; message: string; choices: string[]; }
interface Snapshot { revision: number; state: string; message: string; active: boolean; cleanupRequired: boolean; portal: string; socksPort: number; prompt: Prompt | null; }
interface Settings { portal: string; username: string; socksPort: number; }
interface Credential { portal?: string | null; username: string; password: string; }
const KEY = 'gp-relay.connection-settings.v1';
const $ = <T extends HTMLElement>(id: string) => document.getElementById(id) as T;
$('app-version').textContent = version;
const ui = {
  panel: $('panel'), form: $<HTMLFormElement>('connection-form'), settings: $<HTMLFieldSetElement>('settings'),
  username: $<HTMLInputElement>('username'), password: $<HTMLInputElement>('password'),
  port: $<HTMLInputElement>('socks-port'), remember: $<HTMLInputElement>('remember'), reveal: $<HTMLButtonElement>('toggle-password'),
  status: $('status'), statusText: $('status-text'), error: $('error'), connect: $<HTMLButtonElement>('connect'),
  challenge: $('challenge'), challengeLabel: $('challenge-label'), responseControl: $('response-control'), cancel: $<HTMLButtonElement>('cancel-connection'),
};
let snapshot: Snapshot = { revision: -1, state: 'idle', message: 'Не подключён', active: false, cleanupRequired: false, portal: '', socksPort: 1080, prompt: null };
let ready = false;
let busy = false;
let promptId: string | null = null;
let submittedPrompt: string | null = null;
let infoOpen = false;
let socksCheck = false;
let statusCheck = false;
function readSettings(): Settings {
  const defaults = { portal: 'gp.domru.ru', username: '', socksPort: 1080 };
  try {
    const saved = JSON.parse(localStorage.getItem(KEY) || '{}');
    return { portal: typeof saved.portal === 'string' && saved.portal.trim() ? saved.portal.trim() : defaults.portal,
      username: typeof saved.username === 'string' ? saved.username : '',
      socksPort: Number.isInteger(saved.socksPort) && saved.socksPort > 0 && saved.socksPort <= 65535 ? saved.socksPort : 1080 };
  } catch { return defaults; }
}
function saveSettings() {
  const next: Settings = { portal: settings.portal, username: ui.username.value.trim(), socksPort: Number(ui.port.value) };
  try { localStorage.setItem(KEY, JSON.stringify(next)); } catch { /* still usable for this launch */ }
}
function error(message: unknown = '') { ui.error.textContent = String(message); ui.error.hidden = !message; }
function render() {
  const locked = snapshot.active || snapshot.cleanupRequired;
  ui.settings.disabled = locked || busy || !ready;
  ui.cancel.disabled = busy || !ready || snapshot.state === 'disconnecting';
  ui.cancel.hidden = !snapshot.prompt;
  ui.connect.disabled = ui.cancel.disabled || Boolean(snapshot.prompt && submittedPrompt === snapshot.prompt.requestId);
  ui.connect.textContent = snapshot.state === 'disconnecting' ? 'Отключение…' : snapshot.prompt ? 'Продолжить' : snapshot.state === 'connected' || snapshot.cleanupRequired ? 'Отключить' : snapshot.active ? 'Отменить' : 'Подключить';
  ui.status.dataset.state = snapshot.state;
  ui.status.dataset.waiting = String(Boolean(snapshot.prompt));
  ui.statusText.textContent = snapshot.state === 'error' ? 'Не удалось подключиться' : snapshot.message;
  const p = snapshot.prompt;
  ui.challenge.hidden = !p;
  if (!p) { promptId = null; ui.responseControl.replaceChildren(); }
  else if (promptId !== p.requestId) {
    promptId = p.requestId;
    ui.challengeLabel.textContent = p.message;
    let control: HTMLInputElement | HTMLSelectElement;
    if (p.choices.length) {
      control = document.createElement('select');
      for (const choice of p.choices) { const option = document.createElement('option'); option.value = choice; option.textContent = choice; control.append(option); }
    } else {
      control = document.createElement('input'); control.type = ['password', 'mfa', 'challenge'].includes(p.kind) ? 'password' : 'text';
      control.autocomplete = p.kind === 'mfa' ? 'one-time-code' : 'off';
      control.maxLength = 4096;
      if (p.kind === 'username') control.value = ui.username.value;
    }
    control.id = 'response'; control.required = true;
    ui.responseControl.replaceChildren(control);
    if (document.hasFocus() && !infoOpen) control.focus();
  }
}
function apply(next: Snapshot) {
  if (next.revision < snapshot.revision) return;
  const changed = next.revision !== snapshot.revision;
  snapshot = next;
  if (submittedPrompt !== next.prompt?.requestId) submittedPrompt = null;
  if (changed) error(next.state === 'error' ? next.message : '');
  render();
}
async function refresh() {
  if (!ready || statusCheck) return;
  statusCheck = true;
  try { apply(await invoke<Snapshot>('vpn_status')); }
  catch (e) { error(e); }
  finally { statusCheck = false; }
}
async function checkSocks() {
  if (!ready || socksCheck || snapshot.state !== 'connected') return;
  socksCheck = true;
  try {
    const result = await invoke<{ port: number; listening: boolean }>('socks_status');
    if (snapshot.state === 'connected' && result.port === snapshot.socksPort) {
      ui.statusText.textContent = result.listening ? snapshot.message : 'VPN подключён · прокси недоступен';
    }
  } finally { socksCheck = false; }
}
async function submitResponse() {
  const p = snapshot.prompt;
  const input = $<HTMLInputElement | HTMLSelectElement>('response');
  if (!ready || busy || !p || submittedPrompt === p.requestId || !input || !input.reportValidity()) return;
  const value = input.value;
  submittedPrompt = p.requestId; render(); error();
  try {
    await invoke('vpn_submit_prompt', { requestId: p.requestId, value });
    if (p.kind === 'username') { ui.username.value = value; saveSettings(); }
    if (p.kind === 'password') ui.password.value = value;
    input.value = '';
  } catch (e) { error(e); if (submittedPrompt === p.requestId) submittedPrompt = null; render(); }
}
async function stopConnection() {
  if (!ready || busy || snapshot.state === 'disconnecting') return;
  busy = true; render();
  try { await invoke('vpn_disconnect'); await refresh(); } catch (e) { error(e); }
  finally { busy = false; render(); }
}
ui.form.addEventListener('submit', async event => {
  event.preventDefault();
  if (!ready || busy) return;
  if (snapshot.prompt) { await submitResponse(); return; }
  if (snapshot.active || snapshot.cleanupRequired) {
    await stopConnection(); return;
  }
  if (!ui.form.reportValidity()) return;
  busy = true; render(); error(); saveSettings();
  try {
    await invoke('vpn_connect', { settings: { portal: settings.portal, socksPort: Number(ui.port.value) },
      auth: { username: ui.username.value.trim(), password: ui.password.value, rememberPassword: ui.remember.checked } });
    await refresh();
  } catch (e) { error(e); }
  finally { busy = false; render(); }
});
ui.cancel.addEventListener('click', () => void stopConnection());
ui.responseControl.addEventListener('keydown', e => { if (e.key === 'Enter') { e.preventDefault(); void submitResponse(); } });
ui.reveal.addEventListener('click', () => {
  const show = ui.password.type === 'password'; ui.password.type = show ? 'text' : 'password';
  ui.reveal.setAttribute('aria-pressed', String(show)); ui.reveal.setAttribute('aria-label', show ? 'Скрыть пароль' : 'Показать пароль');
});
ui.username.addEventListener('input', saveSettings);
ui.port.addEventListener('input', saveSettings);
ui.remember.addEventListener('change', async () => { if (!ui.remember.checked) { try { await invoke('credential_delete'); } catch(e) { error(e); } } });
function hidePanel() { void invoke('panel_hide').catch(error); }
function toggleInfo(open: boolean) {
  infoOpen = open;
  $('app-info').hidden = !open;
  ui.form.hidden = open;
  $('show-info').setAttribute('aria-expanded', String(open));
  const port = snapshot.active ? snapshot.socksPort : Number(ui.port.value);
  $('info-proxy').textContent = `socks5h://127.0.0.1:${Number.isInteger(port) && port > 0 && port <= 65535 ? port : 1080}`;
  window.scrollTo(0, 0);
  (open ? $('info-title') : snapshot.prompt ? $('response') : $('show-info'))?.focus({preventScroll: true});
}
$('show-info').addEventListener('click', () => toggleInfo(!infoOpen));
$('close-info').addEventListener('click', () => toggleInfo(false));
$('hide-panel').addEventListener('click', hidePanel);
window.addEventListener('keydown', event => { if (event.key === 'Escape') { event.preventDefault(); hidePanel(); } });
window.addEventListener('focus', () => { void refresh(); });
window.addEventListener('blur', () => { ui.password.type = 'password'; ui.reveal.setAttribute('aria-pressed','false'); ui.reveal.setAttribute('aria-label','Показать пароль'); });
const settings = readSettings();
ui.username.value = settings.username; ui.port.value = String(settings.socksPort);
let lastHeight = 0;
const observer = new ResizeObserver(() => {
  const height = Math.ceil(ui.panel.getBoundingClientRect().height);
  if (ready && height !== lastHeight) { lastHeight = height; void invoke('panel_resize', { height }).catch(() => {}); }
});
observer.observe(ui.panel);
async function setup() {
  try {
    await listen<Snapshot>('vpn://status', ({payload}) => apply(payload));
    await listen('panel://shown', () => {
      void refresh(); void checkSocks().catch(() => {});
      const target = infoOpen ? $('info-title') : snapshot.prompt ? $('response') : ui.username.value ? ui.password.value ? ui.connect : ui.password : ui.username;
      if (document.hasFocus()) target?.focus();
    });
    let credentialError: unknown;
    try {
      const credential = await invoke<Credential | null>('credential_load');
      if (credential && (!credential.portal || credential.portal === settings.portal)) {
        ui.username.value = credential.username; ui.password.value = credential.password;
        ui.remember.checked = true;
      }
    } catch (e) { credentialError = e; }
    ready = true;
    await refresh();
    if (credentialError) error('Не удалось прочитать сохранённый пароль. Введите его заново.');
    await invoke('panel_resize', { height: Math.ceil(ui.panel.getBoundingClientRect().height) });
  } catch (e) { error(e); }
  render();
}
void setup();
window.setInterval(() => { if (document.hasFocus()) { void refresh(); void checkSocks().catch(() => {}); } }, 2000);
