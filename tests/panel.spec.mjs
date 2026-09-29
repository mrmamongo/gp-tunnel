import { test, expect } from '@playwright/test';

async function launch(page, options = {}) {
  await page.addInitScript(options => {
    const callbacks = new Map(), listeners = new Map();
    let n = 0;
    const state = { revision: 0, state: 'idle', message: 'Не подключён', active: false, cleanupRequired: false, portal: '', socksPort: 1080, prompt: null };
    const api = window.__test = { state, calls: [], credential: options.credential ?? null, failLoad: options.failLoad, set(next) {
      Object.assign(state, next);
      for (const id of listeners.get('vpn://status') ?? []) callbacks.get(id)({ event: 'vpn://status', payload: {...state} });
    }};
    if (options.settings) localStorage.setItem('gp-relay.connection-settings.v1', JSON.stringify(options.settings));
    window.__TAURI_INTERNALS__ = {
      transformCallback(fn) { callbacks.set(++n, fn); return n; },
      async invoke(cmd, args) {
        api.calls.push({ cmd, args });
        if (cmd === 'plugin:event|listen') { listeners.set(args.event, [...listeners.get(args.event) ?? [], args.handler]); return args.handler; }
        if (cmd === 'credential_load') { if (api.failLoad) throw 'DPAPI failed'; return api.credential; }
        if (cmd === 'vpn_status') return {...state};
        if (cmd === 'vpn_connect') { api.set({ revision: state.revision+1, state:'preparing', message:'Подготовка подключения…', active:true, socksPort:args.settings.socksPort }); }
        if (cmd === 'vpn_disconnect') { api.set({ revision:state.revision+1,state:'idle',message:'Не подключён',active:false,prompt:null }); }
        if (cmd === 'vpn_submit_prompt') { api.set({ revision:state.revision+1,prompt:null }); }
        if (cmd === 'socks_status') return { port:state.socksPort,listening:true };
        return null;
      },
    };
  }, options);
  await page.goto('/');
  await expect(page.locator('#connect')).toBeEnabled();
}

test('compact form sends configured port and credentials separately, never persists password', async ({page},testInfo) => {
  await launch(page);
  await page.locator('#username').fill('sample-user');
  await page.locator('#password').pressSequentially('sample-secret');
  await page.locator('#panel').screenshot({path:testInfo.outputPath('password.png')});
  await page.locator('#socks-port').fill('2080');
  await page.locator('#connect').click();
  await expect(page.locator('#connect')).toHaveText('Отменить');
  await expect(page.locator('#portal')).toHaveCount(0);
  await expect(page.locator('#username')).toBeDisabled();
  const call = await page.evaluate(() => window.__test.calls.find(c => c.cmd === 'vpn_connect'));
  expect(call.args.settings).toEqual({portal:'gp.domru.ru',socksPort:2080});
  expect(call.args.auth).toEqual({username:'sample-user',password:'sample-secret',rememberPassword:false});
  expect(await page.evaluate(() => JSON.stringify(localStorage))).not.toContain('sample-secret');
});

test('MFA input survives repeated snapshots and cancel works with an empty required challenge', async ({page}) => {
  await launch(page);
  await page.evaluate(() => window.__test.set({revision:1,state:'connecting',active:true,prompt:{requestId:'1-1',kind:'mfa',message:'Одноразовый код',choices:[]}}));
  await page.locator('#response').fill('123456');
  await page.evaluate(() => window.__test.set({revision:2}));
  await expect(page.locator('#response')).toHaveValue('123456');
  await page.locator('#response').fill('');
  await expect(page.locator('#connect')).toHaveText('Продолжить');
  await page.locator('#cancel-connection').click();
  await expect(page.locator('#challenge')).toBeHidden();
  await expect(page.locator('#connect')).toHaveText('Подключить');
});

test('gateway choice is submitted and stale events cannot overwrite the latest state', async ({page}) => {
  await launch(page);
  await page.evaluate(() => window.__test.set({revision:2,state:'connecting',active:true,prompt:{requestId:'1-2',kind:'gateway',message:'Шлюз',choices:['a.example','b.example']}}));
  await page.locator('#response').selectOption('b.example');
  await page.locator('#connect').click();
  expect(await page.evaluate(() => window.__test.calls.find(c => c.cmd === 'vpn_submit_prompt').args)).toEqual({requestId:'1-2',value:'b.example'});
  expect(await page.evaluate(() => window.__test.calls.some(c => c.cmd === 'vpn_disconnect'))).toBe(false);
  await page.evaluate(() => window.__test.set({revision:5,state:'disconnecting',message:'Отключение…',active:true,prompt:null}));
  await page.evaluate(() => window.__test.set({revision:4,state:'connected',message:'Подключён'}));
  await expect(page.locator('#connect')).toHaveText('Отключение…');
});

test('Enter submits MFA without disconnecting and restores the connecting action', async ({page},testInfo) => {
  await launch(page);
  await page.evaluate(() => window.__test.set({revision:1,state:'connecting',active:true,prompt:{requestId:'1-1',kind:'mfa',message:'Одноразовый код',choices:[]}}));
  await page.locator('#response').fill('123456');
  await page.locator('#panel').screenshot({path:testInfo.outputPath('challenge.png')});
  await page.locator('#response').press('Enter');
  expect(await page.evaluate(() => window.__test.calls.find(c => c.cmd === 'vpn_submit_prompt').args)).toEqual({requestId:'1-1',value:'123456'});
  expect(await page.evaluate(() => window.__test.calls.some(c => c.cmd === 'vpn_disconnect'))).toBe(false);
  await expect(page.locator('#connect')).toHaveText('Отменить');
  await expect(page.locator('#connect')).toBeEnabled();
});

test('unclassified challenge keeps the server message and masks the response without sending the saved password', async ({page}) => {
  await launch(page,{credential:{portal:'gp.domru.ru',username:'sample-user',password:'sample-secret'}});
  await page.evaluate(() => window.__test.set({revision:1,state:'connecting',active:true,prompt:{requestId:'1-3',kind:'challenge',message:'Ответ на запрос сервера',choices:[]}}));
  await expect(page.locator('#challenge-label')).toHaveText('Ответ на запрос сервера');
  await expect(page.locator('#response')).toHaveAttribute('type','password');
  await expect(page.locator('#response')).toHaveValue('');
  expect(await page.evaluate(() => window.__test.calls.some(c => c.cmd === 'vpn_submit_prompt'))).toBe(false);
});

test('preserves the configured portal without a host field, migrates legacy credentials and deletes on uncheck', async ({page}) => {
  await launch(page,{settings:{portal:'vpn.example'},credential:{username:'sample-user',password:'sample-secret'}});
  await expect(page.locator('#password')).toHaveValue('sample-secret');
  await expect(page.locator('#socks-port')).toHaveValue('1080');
  await page.locator('#remember').uncheck();
  expect(await page.evaluate(() => window.__test.calls.some(c => c.cmd === 'credential_delete'))).toBe(true);
  await expect(page.locator('#portal')).toHaveCount(0);
  await page.locator('#connect').click();
  expect(await page.evaluate(() => window.__test.calls.find(c => c.cmd === 'vpn_connect').args.settings.portal)).toBe('vpn.example');
});

test('does not load credentials for another portal', async ({page}) => {
  await launch(page,{credential:{portal:'different.example',username:'sample-user',password:'sample-secret'}});
  await expect(page.locator('#password')).toHaveValue('');
  await expect(page.locator('#remember')).not.toBeChecked();
});

test('broken DPAPI does not block manual login', async ({page}) => {
  await launch(page,{credential:{portal:'different.example',username:'sample-user',password:'sample-secret'},failLoad:true});
  await expect(page.locator('#password')).toHaveValue('');
  await expect(page.locator('#username')).toBeEnabled();
  await expect(page.locator('#error')).toContainText('Введите его заново');
});

test('port validation prevents connect and Escape hides without disconnecting', async ({page}) => {
  await launch(page);
  await page.locator('#username').fill('sample-user'); await page.locator('#password').fill('sample-secret');
  await page.locator('#socks-port').fill('65536'); await page.locator('#connect').click();
  expect(await page.evaluate(() => window.__test.calls.some(c => c.cmd === 'vpn_connect'))).toBe(false);
  await page.keyboard.press('Escape');
  expect(await page.evaluate(() => window.__test.calls.some(c => c.cmd === 'panel_hide'))).toBe(true);
  await page.evaluate(() => window.__test.set({revision:1,state:'connected',message:'Подключён',active:true}));
  await page.getByRole('button',{name:'Скрыть окно',exact:true}).click();
  expect(await page.evaluate(() => window.__test.calls.filter(c => c.cmd === 'panel_hide').length)).toBe(2);
  await expect(page.locator('#connect')).toHaveText('Отключить');
  expect(await page.evaluate(() => window.__test.calls.some(c => c.cmd === 'vpn_disconnect'))).toBe(false);
});

test('info preserves a pending MFA response and shows the active SOCKS port', async ({page},testInfo) => {
  await launch(page);
  await page.evaluate(() => window.__test.set({revision:1,state:'connecting',message:'Ожидается ввод',active:true,socksPort:2080,prompt:{requestId:'1-1',kind:'mfa',message:'Одноразовый код',choices:[]}}));
  await page.locator('#response').fill('123456');
  await page.getByRole('button',{name:'О приложении',exact:true}).click();
  await expect(page.locator('#info-title')).toBeFocused();
  await expect(page.locator('#connection-form')).toBeHidden();
  await expect(page.locator('#info-proxy')).toHaveText('socks5h://127.0.0.1:2080');
  await page.evaluate(() => window.__test.set({revision:2}));
  await expect(page.locator('#info-title')).toBeFocused();
  await page.locator('#panel').screenshot({path:testInfo.outputPath('info.png')});
  await page.getByRole('button',{name:'Назад',exact:true}).click();
  await expect(page.locator('#response')).toHaveValue('123456');
  await expect(page.locator('#response')).toBeFocused();
  expect(await page.evaluate(() => window.__test.calls.some(c => ['vpn_disconnect','vpn_submit_prompt'].includes(c.cmd)))).toBe(false);
});

for (const theme of ['light','dark']) {
  test(`layout fits the compact panel in ${theme} theme, including long errors`, async ({page},testInfo) => {
    await page.emulateMedia({colorScheme:theme,reducedMotion:'reduce'});
    await launch(page);
    await expect(page.locator('#panel')).toHaveCSS('width','340px');
    expect(await page.locator('#panel').evaluate(el => el.getBoundingClientRect().height)).toBeLessThan(340);
    await page.locator('#panel').screenshot({path:testInfo.outputPath(`${theme}.png`)});
    await page.evaluate(() => window.__test.set({revision:1,state:'error',message:'Порт 1080 занят. '+ 'very-long-hostname.'.repeat(20),active:false}));
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBe(340);
    await expect(page.locator('#error')).toBeVisible();
  });
}
