# GlobalProtect Remote GUI

Небольшое Windows-приложение на Tauri для запуска локальной headless QEMU VM и управления OpenConnect с протоколом GlobalProtect внутри неё через SSH.

## Что входит в MVP

- запуск существующего загрузочного диска QEMU через WHPX;
- user-mode NAT с SSH-forward только на `127.0.0.1`;
- подключение к VM системным Windows `ssh.exe`;
- интерактивные запросы логина, пароля и MFA-кода;
- статус и отключение foreground OpenConnect;
- локальный SOCKS5-прокси на Windows с настраиваемым портом (по умолчанию `1081`, потому что `1080` уже занят другим локальным SSH SOCKS);
- подробные статусы QEMU, готовности Ubuntu SSH, GlobalProtect и SOCKS в одном окне;
- повторный запуск GUI подхватывает уже работающую Ubuntu по SSH-forward и не перезапускает QEMU;
- relay VM помечена именем `gp-relay`, постоянным UUID и `vm\gp-relay.pid`; GUI сверяет PID с путём к QEMU и подтверждает гостя SSH-ключом;
- журнал QEMU/serial, SSH readiness, OpenConnect и SOCKS без сохранения пароля и MFA;
- хранение несекретных настроек локально; пароль и MFA-код не сохраняются.

## Важные ограничения

- Portable QEMU для Windows x64 находится в `tools\qemu` и исключён из Git. В гостевой Ubuntu должен быть установлен пакет `openconnect`.
- SSH использует ключ или Windows `ssh-agent`; парольная SSH-аутентификация в MVP отключена через `BatchMode=yes`.
- Установленная тестовая VM находится в `vm\ubuntu-gp.qcow2`; пользователь `vpn` входит только по ключу `vm\ssh\gp-relay_ed25519`, а проверенный host key хранится в `vm\ssh\known_hosts`. Каталог `vm` исключён из Git.
- ISO-режим запускает установочный образ read-only для headless smoke/диагностики и не пытается подключать VPN.
- Закрытие GUI не завершает QEMU. При следующем запуске приложение подхватывает работающую VM по SSH-forward. Кнопка остановки VM завершает QEMU принудительно, поэтому перед ней отключите VPN и корректно выключите гостевую ОС.
- VPN работает внутри VM. При включённой настройке GUI поднимает SOCKS5 только на `127.0.0.1`; системный прокси Windows не изменяется. Для приложений используйте `socks5h://127.0.0.1:1081` (или выбранный локальный порт), чтобы DNS-запросы выполнялись через VPN.
- SAML/браузерная авторизация пока не поддерживается. Portal/authgroup/gateway и MFA вводятся через интерактивную панель.

## Разработка

Требуются Node.js, pnpm, Rust toolchain, WebView2 и системный Windows OpenSSH.

```powershell
pnpm install
pnpm build
pnpm tauri dev
```

Для production-сборки:

```powershell
pnpm tauri build
```

## Подготовка VM

Локальная Ubuntu 24.04.4 LTS уже установлена без GUI в `vm\ubuntu-gp.qcow2`. OpenSSH настроен на public-key only, парольный вход отключён, SSH доступен через `127.0.0.1:2222`. OpenConnect 9.12 и `vpnc-script` установлены; подключение к Palo Alto GlobalProtect выполняется через `--protocol=gp`.

Для рабочего режима используются:

- disk image: `vm\ubuntu-gp.qcow2`;
- SSH user: `vpn`;
- identity file: `vm\ssh\gp-relay_ed25519`;
- known hosts: `vm\ssh\known_hosts`;
- forwarded SSH: `127.0.0.1:2222`.

Когда VM имеет статус «Ubuntu доступна по SSH», к ней можно подключиться с Windows напрямую:

```powershell
ssh -p 2222 -i "C:\Work\globalprotect-remote-gui\vm\ssh\gp-relay_ed25519" vpn@127.0.0.1
```

GUI показывает актуальную команду в блоке «Подключение к Ubuntu» и обновляет её при изменении пользователя, ключа или forwarded-порта.

Результаты проверки ISO, unattended-установки и загрузки с диска записаны в `QEMU_SMOKE_TEST.md`.

Установка и проверка OpenConnect описаны в `GP_INSTALL.md`.

Относительные пути разрешаются от каталога `GP Relay.exe`. Старые настройки,
содержащие стандартный путь `C:\Work\globalprotect-remote-gui`, автоматически
переводятся в переносимый вид; произвольные абсолютные пути остаются рабочими.

## Упаковка VM-образа

Сначала корректно выключите Ubuntu (`sudo poweroff`) и дождитесь завершения
QEMU. Упаковщик намеренно откажется читать образ, пока он открыт работающей VM.

```powershell
.\tools\pack-vm-image.ps1
```

Команда не меняет исходный `vm\ubuntu-gp.qcow2`. Она проверяет его,
создаёт компактную копию в новом каталоге `packages\gp-relay-vm-*`, повторно
проверяет результат и записывает `SHA256SUMS.txt` с контрольной суммой.

Для личного переносимого комплекта можно явно добавить каталог с SSH-ключом:

```powershell
.\tools\pack-vm-image.ps1 -IncludeSshIdentity
```

Такой комплект содержит приватный ключ и должен храниться как секрет. Для
передачи другому человеку лучше выпустить отдельную пару ключей, заменить
`authorized_keys` внутри VM и не передавать рабочие VPN-учётные данные.

## Portable-комплект Windows x64

После release-сборки можно создать облегчённый переносимый runtime без VM:

```powershell
pnpm tauri build
.\tools\build-portable.ps1
```

Сценарий включает только Windows x64 QEMU, `qemu-img`, необходимые DLL и
x86-прошивки. Бинарники и прошивки ARM, RISC-V, PowerPC и других архитектур в
комплект не попадают.

Когда VM выключена и упакована предыдущим сценарием, соберите полный комплект:

```powershell
.\tools\build-portable.ps1 -VmPackage .\packages\gp-relay-vm-YYYYMMDD-HHMMSS
```
