#!/usr/bin/env bash
# bastion-open installer: one command from a fresh clone.
#   ./install.sh            scan this machine, print the digest
#   ./install.sh --timer    also install a weekly systemd timer (needs sudo)
set -euo pipefail
cd "$(dirname "$0")"

if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  MODE=docker
elif command -v podman >/dev/null 2>&1; then
  MODE=podman
else
  MODE=native
fi

echo "== bastion-open install (mode: $MODE)"

case "$MODE" in
  docker)
    docker compose build scanner
    docker compose run --rm scanner
    ;;
  podman)
    podman build -t bastion-open:local .
    podman run --rm -v /:/host:ro -v "$(pwd)/config:/app/config:ro" \
      -v bastion-open-data:/data bastion-open:local
    ;;
  native)
    echo "no container runtime found; scanning directly (needs python3, reads root-owned files => sudo)"
    [ -f config/config.yaml ] || cp config/config.example.yaml config/config.yaml
    sudo env BASTION_HOST=/ BASTION_STATE="$PWD/state" python3 scan.py
    ;;
esac

if [ "${1:-}" = "--timer" ]; then
  DEST=/etc/systemd/system
  sudo install -m 0644 deploy/bastion-open.service "$DEST/"
  sudo install -m 0644 deploy/bastion-open.timer "$DEST/"
  sudo sed -i "s|/opt/bastion-open|$PWD|g" "$DEST/bastion-open.service"
  sudo systemctl daemon-reload
  sudo systemctl enable --now bastion-open.timer
  echo "== weekly timer installed ($DEST/bastion-open.timer). Logs: journalctl -u bastion-open.service"
fi

echo
echo "== done. Report: state/report.md (docker: docker run --rm -v bastion-open-data:/data alpine cat /data/report.md)"
echo "== rerun anytime: ./install.sh   or   docker compose run --rm scanner"
