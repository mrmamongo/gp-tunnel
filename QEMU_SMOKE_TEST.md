# QEMU boot smoke test

Дата: 2026-09-12

## Проверенное окружение

- QEMU 11.1.0 (`v11.1.0-12130-ge470268ff4`)
- ускоритель WHPX доступен и успешно запускается
- ISO: `C:\Users\MrMam\Downloads\ubuntu-24.04.4-live-server-amd64.iso`
- SHA-256: `E907D92EEEC9DF64163A7E454CBC8D7755E8DDC7ED42F99DBC80C40F1A138433`

Хэш совпал с опубликованным Canonical `SHA256SUMS`.

## Результат

QEMU был запущен с 2 ГБ RAM, 2 vCPU, WHPX, отключённой сетью, ISO как read-only CD-ROM и локальным monitor на `127.0.0.1`.

- monitor ответил `VM status: running`;
- `info block` подтвердил backing file указанного Ubuntu ISO и read-only режим;
- процесс оставался жив и отвечал;
- QEMU завершён командой monitor `quit`;
- после завершения процесс отсутствует, monitor port закрыт.

Предупреждение `Ignoring request for interrupt vector 0` не остановило загрузку и не является fatal-ошибкой smoke-теста.

## Установка и загрузка с диска

Ubuntu Server 24.04.4 LTS автоматически установлена без GUI в `vm\ubuntu-gp.qcow2` (32 GiB, фактически около 5 GiB). Установщик:

- разметил virtio-диск и установил GRUB;
- установил `openssh-server` и `qemu-guest-agent`;
- применил security updates;
- создал пользователя `vpn` с ключевой авторизацией;
- отключил password и keyboard-interactive SSH authentication;
- успешно выполнил проверку `visudo`.

После установки `qemu-img check` не нашёл ошибок. VM загрузилась с qcow2 через WHPX, SSH был доступен только на `127.0.0.1:2222`. Проверено:

- вход выделенным Ed25519-ключом;
- host key ED25519: `SHA256:4MI/iTYG9k0Fd5ZlImp4RjA5RGpRiaBF5Uu3DjHR8fM`;
- `sudo -n` для пользователя `vpn`;
- активный `sshd`;
- `PasswordAuthentication no`;
- `KbdInteractiveAuthentication no`;
- `AuthenticationMethods publickey`;
- штатное выключение гостя по SSH и остановка QEMU.

Финальный backend-smoke выявил важную привязку: VM была установлена с machine type `q35`, поэтому рабочий запуск также использует `-machine q35,accel=whpx`. При default i440fx менялось имя сетевого интерфейса, установленный netplan не поднимал гостевую сеть, и SSH зависал до banner. После фикса `READY gp-relay`, активный SSH и негативная проверка `Permission denied (publickey)` подтверждены повторно.

GUI теперь подставляет подготовленные disk image, пользователя и identity file по умолчанию. Готовность Disk mode означает успешный SSH `BatchMode` handshake с `StrictHostKeyChecking=yes` и отдельным `vm\ssh\known_hosts`, а не только открытый TCP-порт.

## Что не проверялось

- установка или подключение GlobalProtect;
- проксирование либо маршрутизация трафика Windows через VPN внутри VM;
- SAML/browser-based flow.
