#!/usr/bin/env python3
"""Train the optional phishing classifier (offline; runs locally or on Colab).

Single source of truth for training - the Colab notebook only calls this file,
so the pipeline is reproducible anywhere.

Input : a JSONL file with one sample per line:
        {"id": "...", "label": 1|0, "features": {...}, "source": "..."}
        (produced by tools/build_features.py)
Output: <out>/model.joblib      (sklearn pipeline + metadata)
        <out>/model.onnx       (optional, needs skl2onnx)
        <out>/model_card.json  (machine readable provenance + metrics)
        <out>/model_card.md    (human readable, Vietnamese)

Splitting is done **by group** (id prefix = source corpus) so near-duplicates
of the same mail never end up in both train and test, and one whole corpus can
be held out to measure generalisation.
"""
import argparse
import hashlib
import json
import os
import platform
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def load_rows(path: str):
    rows = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except Exception:
                continue
    return rows


def group_of(row) -> str:
    src = str(row.get("source") or "unknown")
    rid = str(row.get("id") or "")
    return src if src != "unknown" else (rid.split("/")[0] if "/" in rid else "unknown")


def _sha256(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _save_onnx(model, path: Path) -> None:
    """onnx >= 1.16 removed ModelProto.save -> use onnx.save_model."""
    if hasattr(model, "save"):
        model.save(str(path))
        return
    import onnx
    onnx.save_model(model, str(path))


def main() -> int:
    ap = argparse.ArgumentParser(description="Train the phishing classifier")
    ap.add_argument("--features", required=True, help="features.jsonl")
    ap.add_argument("--out", default="data/models", help="output directory")
    ap.add_argument("--model-type", default="both", choices=["lr", "gb", "both"])
    ap.add_argument("--holdout", default="", help="group (source) held out for generalisation")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--min-train", type=int, default=200)
    args = ap.parse_args()

    from app.ml_features import FEATURE_NAMES

    rows = load_rows(args.features)
    labelled = [r for r in rows if r.get("label") in (0, 1)]
    if len(labelled) < args.min_train:
        print(f"!! chỉ có {len(labelled)} mẫu có nhãn (cần >= {args.min_train}) - hãy thu thập thêm dữ liệu")
        return 2
    counts = Counter(int(r["label"]) for r in labelled)
    print(f"Dữ liệu: {len(labelled)} mẫu có nhãn | phishing={counts.get(1,0)} benign={counts.get(0,0)}")
    print("Theo nguồn:", dict(Counter(group_of(r) for r in labelled)))

    import numpy as np
    from sklearn.linear_model import LogisticRegression
    from sklearn.ensemble import HistGradientBoostingClassifier
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import StandardScaler
    from sklearn.calibration import CalibratedClassifierCV
    from sklearn.metrics import (accuracy_score, precision_score, recall_score,
                                 f1_score, roc_auc_score, average_precision_score,
                                 confusion_matrix)

    X = np.asarray([[float((r.get("features") or {}).get(n) or 0) for n in FEATURE_NAMES]
                    for r in labelled], dtype=np.float32)
    y = np.asarray([int(r["label"]) for r in labelled], dtype=np.int32)
    groups = [group_of(r) for r in labelled]

    # --- split: hold one whole group out (generalisation), rest grouped split ---
    hold = args.holdout or None
    uniq = sorted(set(groups))

    def group_split(h):
        te = [i for i, g in enumerate(groups) if g == h]
        tr = [i for i, g in enumerate(groups) if g != h]
        return tr, te

    def stratified_split():
        from sklearn.model_selection import train_test_split
        idx = list(range(len(labelled)))
        tr, te = train_test_split(idx, test_size=0.25, random_state=args.seed,
                                  stratify=y if len(set(y)) > 1 else None)
        return list(tr), list(te)

    tr_idx = te_idx = None
    split_mode = ""
    if hold and hold in set(groups):
        tr_idx, te_idx = group_split(hold)
        split_mode = "group-holdout"
    elif len(uniq) > 1:
        hold = uniq[-1]
        tr_idx, te_idx = group_split(hold)
        split_mode = "group-holdout"
    if tr_idx is not None:
        # a hold-out that leaves only one class in the training set is useless
        if len(set(y[tr_idx])) < 2 or len(te_idx) < 10:
            print("(!) hold-out theo nhóm làm tập train chỉ còn 1 lớp -> chuyển sang chia ngẫu nhiên có phân tầng")
            hold = None
            tr_idx, te_idx = stratified_split()
            split_mode = "random-stratified"
    else:
        tr_idx, te_idx = stratified_split()
        hold = None
        split_mode = "random-stratified"
    if len(tr_idx) < 50 or len(te_idx) < 10:
        print("!! không đủ dữ liệu để chia tập")
        return 2
    print(f"Tập train={len(tr_idx)} (nhóm: {sorted(set(groups[i] for i in tr_idx))}) | "
          f"hold-out={hold}: {len(te_idx)} [{split_mode}]")

    def build(kind: str):
        if kind == "lr":
            base = Pipeline([("scale", StandardScaler()),
                             ("clf", LogisticRegression(C=1.0, class_weight="balanced",
                                                        max_iter=2000, solver="lbfgs"))])
        else:
            base = Pipeline([("scale", StandardScaler()),
                             ("clf", HistGradientBoostingClassifier(
                                 max_iter=300, learning_rate=0.06, max_leaf_nodes=15,
                                 min_samples_leaf=50, l2_regularization=1.0,
                                 class_weight="balanced", random_state=args.seed))])
        try:
            return CalibratedClassifierCV(base, method="sigmoid", cv=5)
        except Exception:
            return base

    def metrics(model, Xte, yte):
        p = model.predict_proba(Xte)[:, 1]
        pred = (p >= 0.5).astype(int)
        out = {
            "accuracy": round(float(accuracy_score(yte, pred)), 4),
            "precision": round(float(precision_score(yte, pred, zero_division=0)), 4),
            "recall": round(float(recall_score(yte, pred, zero_division=0)), 4),
            "f1": round(float(f1_score(yte, pred, zero_division=0)), 4),
        }
        try:
            out["roc_auc"] = round(float(roc_auc_score(yte, p)), 4)
            out["pr_auc"] = round(float(average_precision_score(yte, p)), 4)
        except Exception:
            pass
        out["confusionMatrix"] = confusion_matrix(yte, pred, labels=[0, 1]).tolist()
        out["positiveRate"] = round(float((pred == 1).mean()), 4)
        return out

    candidates = []
    for kind in (["lr", "gb"] if args.model_type == "both" else [args.model_type]):
        model = build(kind)
        model.fit(X[tr_idx], y[tr_idx])
        m = metrics(model, X[te_idx], y[te_idx])
        print(f"[{kind}] hold-out metrics: {json.dumps(m, ensure_ascii=False)}")
        candidates.append((kind, model, m))

    # selection rule: the tree model must beat LR by >= 0.03 F1 AND not lose recall
    lr = next((c for c in candidates if c[0] == "lr"), None)
    gb = next((c for c in candidates if c[0] == "gb"), None)
    if gb and lr:
        better = (gb[2].get("f1", 0) - lr[2].get("f1", 0)) >= 0.03 and \
                 gb[2].get("recall", 0) >= lr[2].get("recall", 0)
        chosen = gb if better else lr
        print(f"=> chọn {chosen[0]} (LR được ưu tiên khi không vượt rõ rệt)")
    else:
        chosen = candidates[0]
    kind, model, met = chosen

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    version = time.strftime("%Y%m%d-%H%M%S")
    card = {
        "version": version,
        "modelType": kind,
        "trainedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "featureNames": list(FEATURE_NAMES),
        "nSamples": len(labelled),
        "labelCounts": {"phishing": counts.get(1, 0), "benign": counts.get(0, 0)},
        "sources": dict(Counter(groups)),
        "trainSize": len(tr_idx),
        "holdout": {"group": hold, "size": len(te_idx), "mode": split_mode},
        "metrics": met,
        "threshold": 0.70,
        "seed": args.seed,
        "featuresFile": os.path.basename(args.features),
        "featuresSha256": hashlib.sha256(open(args.features, "rb").read()).hexdigest(),
        "python": platform.python_version(),
        "libraries": {},
    }
    try:
        import sklearn, numpy, scipy, joblib
        card["libraries"] = {"scikit-learn": sklearn.__version__, "numpy": numpy.__version__,
                             "scipy": scipy.__version__, "joblib": joblib.__version__}
    except Exception:
        pass

    import joblib
    joblib.dump({"model": model, "meta": card, "featureNames": list(FEATURE_NAMES)},
                out_dir / "model.joblib")
    card["modelSha256"] = _sha256(out_dir / "model.joblib")
    (out_dir / "model_card.json").write_text(json.dumps(card, ensure_ascii=False, indent=2), encoding="utf-8")
    try:
        import skl2onnx
        from skl2onnx.common.data_types import FloatTensorType
        onx = skl2onnx.to_onnx(model, initial_types=[("float_input", FloatTensorType([None, len(FEATURE_NAMES)]))],
                              target_opset=15, options={id(model): {"zipmap": False}})
        onx.metadata_props.add(key="model_card", value=json.dumps(card)[:8000])
        _save_onnx(onx, out_dir / "model.onnx")
        card["modelSha256"] = _sha256(out_dir / "model.joblib")
        (out_dir / "model_card.json").write_text(json.dumps(card, ensure_ascii=False, indent=2), encoding="utf-8")
        print("→ model.onnx đã xuất")
    except Exception as e:
        print(f"(!) không xuất được ONNX: {type(e).__name__}: {e}")

    (out_dir / "model_card.json").write_text(json.dumps(card, ensure_ascii=False, indent=2), encoding="utf-8")
    md = [
        "# Model card — bộ phân loại phishing (MailSleuth M10)", "",
        f"- **Phiên bản**: {version} · **Kiểu**: {kind} · **Ngày train**: {card['trainedAt']}",
        f"- **Mẫu**: {card['nSamples']} (phishing={card['labelCounts']['phishing']}, "
        f"benign={card['labelCounts']['benign']}) · train={len(tr_idx)} · hold-out={hold} ({len(te_idx)})",
        f"- **Nguồn dữ liệu**: {card['sources']}",
        f"- **Hash tập đặc trưng**: `{card['featuresSha256'][:16]}…`",
        f"- **Thư viện**: {card['libraries']}", "",
        "## Kết quả trên tập hold-out (nhóm corpus chưa thấy)", "",
        "| Chỉ số | Giá trị |", "|---|---|",
    ]
    for k, v in met.items():
        if k != "confusionMatrix":
            md.append(f"| {k} | {v} |")
    cm = met.get("confusionMatrix") or []
    md += ["", "**Ma trận nhầm lẫn** (`[[TN, FP], [FN, TP]]`):", "", "```", json.dumps(cm), "```", "",
           "## Giới hạn", "",
           "- Đặc trưng **không** dùng kết quả DNS sống (SPF/DKIM/DMARC) để tránh lệch phân phối giữa lúc train và lúc chạy.",
           "- Không chứa chuỗi thô (tên miền, IP, tên tệp, nội dung thư) → có thể chia sẻ an toàn.",
           "- Chỉ là **tín hiệu tham chiếu**: verdict cuối luôn là hợp nhất với tầng rule.",
           "- Nguồn công khai đều cũ (2005–2021) → cần nhãn nội bộ để đạt độ chính xác thực tế.", ""]
    (out_dir / "model_card.md").write_text("\n".join(md), encoding="utf-8")
    print(f"→ model.joblib + model_card.json/md đã lưu vào {out_dir}")
    return 0


if __name__ == "__main__":
    import time
    sys.exit(main())
