# OpenConnect для GlobalProtect

## Current status

- Guest: Ubuntu Server 24.04.4 LTS, amd64, no GUI.
- Доступность корпоративного портала из гостя проверена по HTTPS.
- OpenConnect 9.12 установлен в тестовой VM.
- Подключение запускается в foreground через SSH PTY; логин, пароль, OTP/passcode и выбор authgroup/gateway вводятся в GUI.

## Установка

```bash
sudo apt update
sudo apt install openconnect
```

Пакет устанавливается внутри Ubuntu VM. В подготовленном образе пользователь `vpn` имеет ограниченный для этой локальной VM passwordless sudo; backend использует `sudo -n`, поэтому системный пароль не запрашивается и не смешивается с паролем VPN.

## Ручная проверка

```bash
command -v openconnect
openconnect --version
sudo openconnect --protocol=gp gp.domru.ru
```

В GUI достаточно указать SSH relay и portal (`gp.domru.ru`), затем нажать «Подключить». Кнопка «Отключить» посылает `Ctrl-C` foreground-процессу OpenConnect, после чего удалённая shell-сессия закрывается.

Подключение к корпоративному порталу не выполняется автоматически во время установки или сборки.
