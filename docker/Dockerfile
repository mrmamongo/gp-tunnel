# gp-relay-alpine: VPN-релей в контейнере (вместо qemu VM)
# gpclient (GlobalProtect-openconnect) + dante SOCKS5 + sshd
FROM alpine:3.20

RUN apk add --no-cache \
      openconnect openssh-server dante-server shadow sudo bash socat \
      iproute2 iptables curl ca-certificates

# юзер + ssh
RUN addgroup -S vpn && adduser -S -G vpn -s /bin/bash vpn \
    && echo "vpn ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/vpn \
    && mkdir -p /var/run/sshd /home/vpn/.ssh \
    && ssh-keygen -A

# конфиг dante: SOCKS5 на все интерфейсы, через tun (появится от gpclient)
COPY dante.conf /etc/sockd.conf
COPY entry.sh /entry.sh
RUN chmod +x /entry.sh

EXPOSE 1080 22

ENTRYPOINT ["/entry.sh"]
