# OpenConnect для GlobalProtect

## Current status

- Relay: контейнер `gp-relay` (Alpine + openconnect + dante + sshd).
- Доступность корпоративного портала проверена по HTTPS из контейнера.
- OpenConnect 9.12 (Alpine package) стоит в образе `ghcr.io/mrmamongo/gp-relay:latest`.
- Подключение запускается в foreground внутри контейнера через `docker exec` + PTY;
  логин, пароль, OTP/passcode и выбор authgroup/gateway вводятся в GUI.

## Установка

```bash
docker pull ghcr.io/mrmamongo/gp-relay:latest
```

openconnect и `vpnc-script` уже входят в образ; отдельная установка не нужна.
При сборке образа из исходников используется `docker/Dockerfile`.

## Ручная проверка

```bash
docker run --rm -it --cap-add=NET_ADMIN --device=/dev/net/tun \
  ghcr.io/mrmamongo/gp-relay:latest openconnect --version
docker exec -it gp-relay openconnect --protocol=gp gp.domru.ru
```

В GUI достаточно указать портал (`gp.domru.ru`) и нажать «Подключить»: GUI сам
проверит и поднимет контейнер. Кнопка «Отключить» посылает `Ctrl-C`
foreground-процессу OpenConnect внутри PTY контейнера.

Подключение к корпоративному порталу не выполняется автоматически во время
установки или сборки.
