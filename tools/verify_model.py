#!/usr/bin/env python3
"""Gate keeper for the model file: verify before deploying it to the server.

Checks
  1. the file exists and its SHA-256 matches model_card.json
  2. the feature schema matches app/ml_features.FEATURE_NAMES exactly
  3. the model loads (ONNX via onnxruntime, or joblib via scikit-learn)
  4. a sanity prediction on a synthetic feature vector works

Exit code 0 = safe to deploy, 1 = refuse.
"""
import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.ml_features import FEATURE_NAMES  # noqa: E402


def sha256(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser(description="Verify a model file before deployment")
    ap.add_argument("model", help="path to model.onnx or model.joblib")
    ap.add_argument("--card", default="", help="model_card.json (default: next to the model)")
    args = ap.parse_args()

    path = Path(args.model)
    if not path.exists():
        print("FAIL: không có file model:", path)
        return 1
    card_path = Path(args.card) if args.card else path.parent / "model_card.json"
    card = {}
    if card_path.exists():
        card = json.loads(card_path.read_text(encoding="utf-8"))
    else:
        print("WARN: không có model_card.json - không kiểm được hash/feature list")

    # 1. hash (the model file itself; the card also carries the dataset hash)
    want = card.get("modelSha256")
    if want:
        got = sha256(path)
        if want != got:
            print(f"FAIL: SHA-256 của file model không khớp model card\n  card: {want}\n  file: {got}")
            return 1
        print("PASS: SHA-256 file model khớp model card")
    else:
        print("WARN: model card không có modelSha256 - bỏ qua kiểm tra hash file")

    # 2. feature schema
    names = card.get("featureNames")
    if names:
        if list(names) != list(FEATURE_NAMES):
            print("FAIL: feature schema lệch với app/ml_features.py")
            miss = set(FEATURE_NAMES) - set(names)
            extra = set(names) - set(FEATURE_NAMES)
            print(f"  thiếu: {sorted(miss)}\n  thừa : {sorted(extra)}")
            return 1
        print(f"PASS: feature schema khớp ({len(FEATURE_NAMES)} đặc trưng)")
    else:
        print("WARN: model card không khai báo featureNames - bỏ qua kiểm tra schema")

    # 3+4. load + predict
    try:
        if path.suffix == ".onnx":
            import numpy as np
            import onnxruntime as ort
            sess = ort.InferenceSession(str(path), providers=["CPUExecutionProvider"])
            inp = sess.get_inputs()[0]
            shape = getattr(inp, "shape", None)
            if shape and isinstance(shape[1], int) and shape[1] != len(FEATURE_NAMES):
                print(f"FAIL: model đợi {shape[1]} đặc trưng nhưng code có {len(FEATURE_NAMES)}")
                return 1
            out = sess.run(None, {inp.name: np.zeros((1, len(FEATURE_NAMES)), dtype=np.float32)})
            print("PASS: ONNX nạp và suy luận được ->", list(out[0][0])[:4])
        else:
            import joblib
            obj = joblib.load(str(path))
            model = obj.get("model") if isinstance(obj, dict) else obj
            names2 = obj.get("featureNames") if isinstance(obj, dict) else None
            if names2 and list(names2) != list(FEATURE_NAMES):
                print("FAIL: feature schema lệch (joblib)")
                return 1
            prob = model.predict_proba([[0.0] * len(FEATURE_NAMES)])[0][1]
            print("PASS: joblib nạp và suy luận được -> p =", round(float(prob), 4))
    except Exception as e:
        print(f"FAIL: không nạp được model: {type(e).__name__}: {e}")
        return 1

    print("\n=> an toàn để triển khai.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
