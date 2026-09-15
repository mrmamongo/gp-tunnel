# gp-relay: VPN-релей в контейнере (docker-путь GUI).
# openconnect (протокол GlobalProtect) + dante SOCKS5 + socat (PTY для openconnect).
FROM alpine:3.20

RUN apk add --no-cache \
      openconnect dante-server socat bash curl ca-certificates \
      iproute2 iptables

# конфиг dante: SOCKS5 на все интерфейсы, через tun (появится от openconnect)
COPY dante.conf /etc/sockd.conf
COPY entry.sh /entry.sh
RUN chmod +x /entry.sh

EXPOSE 1080

ENTRYPOINT ["/entry.sh"]
