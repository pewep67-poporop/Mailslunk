#!/usr/bin/env bash
# Chạy từng file test riêng biệt (mỗi file có DATA_DIR riêng).
# Dùng thay cho `python -m unittest discover` vì discover dùng chung DATA_DIR.
set -u
cd "$(dirname "$0")/.."
pass=0; fail=0
for f in tests/test_*.py; do
  if python3 "$f" >/tmp/unit_out.txt 2>&1; then
    echo "PASS $(basename "$f")"; pass=$((pass+1))
  else
    echo "FAIL $(basename "$f")"; tail -5 /tmp/unit_out.txt; fail=$((fail+1))
  fi
done
echo "RESULT: $pass PASS / $fail FAIL"
exit $fail
