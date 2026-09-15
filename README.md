# GlobalProtect Remote GUI

Небольшое Windows-приложение на Tauri для управления OpenConnect с протоколом
GlobalProtect, который работает в локальном docker-контейнере `gp-relay`.

## Как это устроено

VPN-релей — контейнер **61 МБ**, который тянется из публичного реестра и
поднимается GUI автоматически перед подключением.

```bash
docker run -d --name gp-relay --cap-add=NET_ADMIN --device=/dev/net/tun \
  -p 1080:1080 -p 2222:22 --restart unless-stopped \
  ghcr.io/mrmamongo/gp-relay:latest
docker exec -it gp-relay openconnect --protocol=gp gp.domru.ru   # логин + OTP
```

Внутри: Alpine + `openconnect` (протокол GlobalProtect) + dante (SOCKS5 на
`:1080`) + sshd (`:2222`). Надзиратель в `entry.sh` сам перепривязывает dante к IP
туннеля, как только появится `tun0` — IP меняется от сессии к сессии, руками
править не нужно.

В GUI нужно указать только портал GlobalProtect: при подключении приложение
само проверяет/поднимает контейнер, запускает `openconnect` внутри него
(`docker exec` + PTY через `socat`) и ведёт интерактивную сессию — промпты
логина, пароля и MFA приходят в окно приложения.

| | Значение |
|---|---|
| Backend | docker-контейнер `gp-relay` (путь единственный) |
| Вес образа | 61 МБ |
| Холодный старт | `docker pull` → `docker run` |
| Менеджмент | `docker ps`, `docker exec`, логи контейнера |
| SOCKS5 | dante в контейнере, `socks5h://127.0.0.1:1080` |
| SSH внутрь контейнера | `ssh -p 2222 vpn@127.0.0.1` |

Сборка и публикация образа — workflow `.github/workflows/docker-image.yml`
(пушит `ghcr.io/mrmamongo/gp-relay:latest` + sha-тег при изменениях в `docker/**`).

## Что умеет GUI

- проверяет и при необходимости поднимает контейнер `gp-relay` перед подключением;
- запускает foreground `openconnect --protocol=gp <portal>` внутри контейнера;
- интерактивные запросы логина, пароля, OTP/passcode и authgroup/gateway;
- статус и отключение OpenConnect (Ctrl-C в PTY контейнера);
- индикатор SOCKS5 `127.0.0.1:1080` (dante внутри контейнера, GUI порт не открывает);
- хранение несекретных настроек локально; пароль и MFA-код не сохраняются,
  а по желанию защищаются Windows DPAPI (`credential_save/load/delete`).

## Важные ограничения

- Требуется запущенный Docker Desktop (или другой docker CLI в `PATH`).
- Поддерживается только docker-бэкенд: QEMU/VM-путь и локальный SOCKS через
  `ssh -D` удалены из приложения.
- SOCKS5 слушает на `127.0.0.1:1080` и его поднимает сам контейнер; системный
  прокси Windows не изменяется. Для приложений используйте
  `socks5h://127.0.0.1:1080`, чтобы DNS-запросы выполнялись через VPN.
- SAML/браузерная авторизация пока не поддерживается. Portal/authgroup/gateway
  и MFA вводятся через интерактивную панель.
- Закрытие GUI не останавливает контейнер и openconnect: контейнер живёт с
  `--restart unless-stopped`, а сессию следует завершать кнопкой «Отключить».
  Удалить контейнер целиком — `docker rm -f gp-relay`.

## Разработка

Требуются Node.js, pnpm, Rust toolchain, WebView2 и docker CLI.

```powershell
pnpm install
pnpm build
pnpm tauri dev
```

Для production-сборки:

```powershell
pnpm tauri build
```

Проверки перед коммитом:

```powershell
cd src-tauri; cargo check
npx tsc -p tsconfig.json --noEmit
```

Проверки backend-команд: `docker_exec`, `socks_probe`, `docker_vpn_status`
(`src-tauri/src/docker.rs`), запуск сессии — `start_connection` в
`src-tauri/src/lib.rs`. Frontend-docker-логика — `src/main.ts`
(`DOCKER_CONTAINER`, `DOCKER_IMAGE`, `dockerEnsureContainer`), совместимый
API-слой — `src/backend-docker.ts`.

## Прочее

Установка и проверка OpenConnect описаны в `GP_INSTALL.md`.
