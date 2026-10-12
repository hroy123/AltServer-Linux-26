#!/usr/bin/env bash
# Optional systemd setup for AltServer-Linux-26 and netmuxd.
# Review your local usbmuxd/netmuxd arrangement before enabling netmuxd.
set -Eeuo pipefail

if (( EUID != 0 )); then
  echo "Run with sudo and supply absolute paths: sudo ALT_BIN=/path/... NETMUXD_BIN=/path/... ./install-startup-services.sh" >&2
  exit 1
fi
: "${ALT_BIN:?Set ALT_BIN to the absolute AltServer-aarch64 path}"
: "${NETMUXD_BIN:?Set NETMUXD_BIN to the absolute netmuxd executable path}"
ANISETTE_URL="${ANISETTE_URL:-http://127.0.0.1:6970}"
SERVICE_USER="${SERVICE_USER:-opi}"

for bin in "$ALT_BIN" "$NETMUXD_BIN"; do
  if [[ "$bin" != /* || ! -f "$bin" || ! -x "$bin" ]]; then
    echo "Not an executable absolute path: $bin" >&2
    exit 1
  fi
done
if ! id "$SERVICE_USER" >/dev/null 2>&1; then
  echo "User not found: $SERVICE_USER" >&2
  exit 1
fi

for unit in altserver-26.service netmuxd-26.service; do
  if [[ -e "/etc/systemd/system/$unit" ]]; then
    echo "Already exists: $unit; refusing to overwrite." >&2
    exit 1
  fi
done

if systemctl is-active --quiet usbmuxd.service; then
  echo "usbmuxd.service is active. Check your netmuxd setup before enabling both services." >&2
  echo "Nothing has been changed." >&2
  exit 1
fi

alt_dir="$(dirname "$ALT_BIN")"
cat > /etc/systemd/system/netmuxd-26.service <<EOF
[Unit]
Description=netmuxd for AltServer-Linux-26
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$NETMUXD_BIN
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/altserver-26.service <<EOF
[Unit]
Description=AltServer-Linux-26
After=network-online.target netmuxd-26.service docker.service
Wants=network-online.target
Requires=netmuxd-26.service

[Service]
Type=simple
User=$SERVICE_USER
WorkingDirectory=$alt_dir
Environment="ALTSERVER_ANISETTE_SERVER=$ANISETTE_URL"
ExecStart=$ALT_BIN
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
echo "Service files installed (not started). Review them:"
echo "  sudo systemctl cat netmuxd-26.service altserver-26.service"
echo "After stopping any manually running Screen instances and confirming usbmuxd arrangements:"
echo "  sudo systemctl enable --now netmuxd-26.service altserver-26.service"
echo "  systemctl status netmuxd-26.service altserver-26.service"
