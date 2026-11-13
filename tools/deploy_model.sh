#!/usr/bin/env bash
# Deploy a trained model to the MailSleuth server (Linux) and restart it safely.
#
#   bash tools/deploy_model.sh /path/to/models           # local folder
#   bash tools/deploy_model.sh /path/to/models --dry-run
#
# Steps: verify (sha256 + feature schema) -> copy -> enable -> restart -> health check
set -euo pipefail

SRC="${1:-}"
DRY=0
[ "${2:-}" = "--dry-run" ] && DRY=1
APP_DIR="${APP_DIR:-/opt/mailsleuth_python}"
DATA_DIR="${DATA_DIR:-./data}"
SERVICE="${SERVICE:-mailsleuth}"

if [ -z "$SRC" ]; then
  echo "Dùng: bash tools/deploy_model.sh <thư mục chứa model.onnx|model.joblib> [--dry-run]"
  exit 2
fi
if [ ! -f "$SRC/model.onnx" ] && [ ! -f "$SRC/model.joblib" ]; then
  echo "!! không thấy model.onnx / model.joblib trong $SRC"
  exit 2
fi

echo "== 1. kiểm tra model (sha256 + schema đặc trưng)"
python3 "$APP_DIR/tools/verify_model.py" "$SRC/model.onnx" 2>/dev/null \
  || python3 "$APP_DIR/tools/verify_model.py" "$SRC/model.joblib"

if [ "$DRY" = "1" ]; then
  echo "(dry-run) sẽ copy vào $APP_DIR/data/models/ rồi restart $SERVICE"
  exit 0
fi

echo "== 2. copy model vào $APP_DIR/data/models"
mkdir -p "$APP_DIR/data/models"
cp -f "$SRC"/model.* "$APP_DIR/data/models/" 2>/dev/null || true
cp -f "$SRC/model_card.json" "$SRC/model_card.md" "$APP_DIR/data/models/" 2>/dev/null || true
chmod 644 "$APP_DIR/data/models/"*.onnx "$APP_DIR/data/models/"*.joblib 2>/dev/null || true
chmod 600 "$APP_DIR/data/models/model_card.json" 2>/dev/null || true

echo "== 3. bật ML trong systemd"
SERVICE_FILE="/etc/systemd/system/$SERVICE.service"
if [ -f "$SERVICE_FILE" ]; then
  if ! grep -q "^Environment=ML_ENABLED=1" "$SERVICE_FILE"; then
    sed -i 's|^#Environment=ML_ENABLED=1|Environment=ML_ENABLED=1|' "$SERVICE_FILE"
    systemctl daemon-reload
  fi
  systemctl restart "$SERVICE"
  sleep 3
  echo "== 4. kiểm tra sức khoẻ"
  curl -fsS "http://127.0.0.1:${PORT:-8000}/api/health?deep=1" | python3 -c "import json,sys; d=json.load(sys.stdin); print('ml:', (d.get('components') or {}).get('ml'))"
else
  echo "!! không thấy $SERVICE_FILE — copy model xong, hãy tự bật ML_ENABLED=1 và restart"
fi

echo "== 5. dọn dấu vết cũ (tuỳ chọn)"
python3 "$APP_DIR/tools/purge.py" --staging --apply || true
echo "=> xong."
