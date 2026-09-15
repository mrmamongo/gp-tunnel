#!/bin/bash
# entry: dante (SOCKS5) стартует сразу; надзиратель перепривязывает его к tun0,
# как только появится туннель. openconnect запускает GUI через docker exec + socat
# (socat даёт openconnect PTY, наружу торчит пайпами).
mkdir -p /dev/net || true
[ -c /dev/net/tun ] || mknod /dev/net/tun c 10 200 2>/dev/null || true

# стартовый dante: eth0 (интернет до туннеля)
sockd -D -f /etc/sockd.conf || true

# надзиратель: при появлении tun0 с новым IP — пересобрать конфиг и рестартнуть dante
(
  while true; do
    TUNIP=$(ip -4 addr show tun0 2>/dev/null | grep -oE 'inet [0-9.]+' | awk '{print $2}')
    if [ -n "$TUNIP" ]; then
      if ! grep -q "^external: ${TUNIP}$" /etc/sockd.runtime.conf 2>/dev/null; then
        sed "s/^external: .*/external: ${TUNIP}/" /etc/sockd.conf > /etc/sockd.runtime.conf
        pkill sockd 2>/dev/null
        sleep 1
        sockd -D -f /etc/sockd.runtime.conf || true
        echo "$(date +%T) dante rebound to tun0=${TUNIP}"
      fi
    fi
    sleep 5
  done
) &

if [ $# -eq 0 ]; then
  echo "gp-relay ready: SOCKS5 на :1080 (перепривяжется к tun0 после подключения)."
  echo "Подключение — из GUI (docker exec + socat + openconnect)."
  sleep infinity
else
  exec "$@"
fi
