# OpenConnect для GlobalProtect

Relay работает в контейнере `gp-relay`: Alpine + OpenConnect + Dante + socat.
Приложение получает образ самостоятельно при нажатии «Подключить».

```powershell
docker pull ghcr.io/mrmamongo/gp-relay:latest
```

Для ручной диагностики отдельного контейнера:

```powershell
docker run -d --name gp-relay --cap-add=NET_ADMIN --device=/dev/net/tun -p 127.0.0.1:1080:1080 --restart unless-stopped ghcr.io/mrmamongo/gp-relay:latest
docker exec -it gp-relay openconnect --protocol=gp gp.domru.ru
```

Завершите ручную сессию до подключения через GUI. Панель открывается по значку в трее; закрытие панели сохраняет VPN, команда «Выйти» отключает его. Порт SOCKS выбирается до подключения, внутри контейнера остаётся `1080`.

Установка и сборка не выполняют подключение к корпоративному порталу.
