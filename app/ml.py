"""M10 — Optional trained classifier (inference side).

The server never trains anything: it only loads a model file produced by
`tools/train_model.py` (ONNX preferred, joblib accepted) and scores a case.

Safety contract:
  * **Absent model -> no-op.** The server behaves exactly as before.
  * **Broken model -> no-op.** A model that cannot be loaded, or whose feature
    schema does not match `app/ml_features.FEATURE_NAMES`, is refused and
    logged; the server keeps running rule-only.
  * The ML score is **advisory**: it may raise the suspicion level, it never
    lowers a rule verdict (see main.py).
"""
import os
import threading

from .ml_features import FEATURE_NAMES, feature_vector

MODEL_PATH = os.getenv("ML_MODEL_PATH", "") or ""
ENABLED = os.getenv("ML_ENABLED", "0") == "1"
THRESHOLD = float(os.getenv("ML_THRESHOLD", "0.70") or 0.70)

_lock = threading.Lock()
_state = {"state": "absent", "model": None, "version": None, "error": ""}
_loaded = False


def status() -> dict:
    """For /api/health?deep=1 — never exposes anything sensitive."""
    if _state["state"] == "absent":
        load()          # lazy: report the real state instead of "absent"
    with _lock:
        return {"state": _state["state"], "version": _state["version"],
                "error": _state["error"], "enabled": ENABLED,
                "threshold": THRESHOLD, "features": len(FEATURE_NAMES)}


def _path() -> str:
    if MODEL_PATH:
        return MODEL_PATH
    from .db import data_dir
    for cand in ("phish_model.onnx", "phish_model.joblib"):
        p = data_dir() / "models" / cand
        if p.exists():
            return str(p)
    return ""


def load():
    """Load the model once (thread-safe). Returns the model or None."""
    global _loaded
    with _lock:
        if _loaded:
            return _state["model"]
        _loaded = True
        path = _path()
        if not path or not os.path.exists(path):
            _state.update({"state": "absent", "model": None, "version": None, "error": ""})
            return None
        try:
            if path.endswith(".onnx"):
                import onnxruntime as ort
                sess = ort.InferenceSession(path, providers=["CPUExecutionProvider"])
                meta = _read_meta(path)
                _state.update({"state": "loaded", "model": sess, "version": meta.get("version"),
                               "error": ""})
            else:
                import joblib
                obj = joblib.load(path)
                meta = obj.get("meta", {}) if isinstance(obj, dict) else {}
                _state.update({"state": "loaded", "model": obj, "version": meta.get("version"),
                               "error": ""})
        except Exception as e:
            _state.update({"state": "error", "model": None, "version": None,
                           "error": f"{type(e).__name__}: {e}"[:200]})
            return None
        return _state["model"]


def _read_meta(path: str) -> dict:
    import json
    p = os.path.join(os.path.dirname(path), "model_card.json")
    try:
        with open(p, encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return {}


def _schema_ok(model) -> bool:
    """The model must expect exactly our feature order."""
    try:
        names = None
        if hasattr(model, "input_names"):        # onnxruntime
            names = [n for n in model.input_names if n != "float_input"]
            inp = model.get_inputs()[0]
            shape = getattr(inp, "shape", None)
            if shape and isinstance(shape[1], int) and shape[1] != len(FEATURE_NAMES):
                return False
        elif isinstance(model, dict):
            names = model.get("featureNames")
        if names and list(names) != list(FEATURE_NAMES):
            return False
        return True
    except Exception:
        return False


def score_result(result: dict) -> dict:
    """-> {mlScore, mlProb, mlVerdict, topFactors[], modelVersion} or {} when off."""
    if not ENABLED:
        return {}
    model = load()
    if model is None:
        return {}
    if not _schema_ok(model):
        with _lock:
            _state.update({"state": "error", "model": None,
                           "error": "feature schema mismatch - model refused"})
        return {}
    x = feature_vector(result)
    est = model.get("model") if isinstance(model, dict) else model
    try:
        if hasattr(est, "run"):                # onnxruntime session
            import numpy as np
            inp = est.get_inputs()[0]
            name = inp.name
            prob = None
            for out in est.get_outputs():
                arr = est.run([out.name], {name: np.asarray([x], dtype=np.float32)})
                prob = float(arr[0][0])
                break
            if prob is None:
                return {}
        else:
            prob = float(est.predict_proba([x])[0][1])
    except Exception as e:
        with _lock:
            _state.update({"error": f"inference failed: {type(e).__name__}"})
        return {}
    verdict = "phishing" if prob >= max(0.9, THRESHOLD + 0.2) else (
        "suspicious" if prob >= THRESHOLD else "clean")
    return {"mlScore": int(round(prob * 100)), "mlProb": round(prob, 4),
            "mlVerdict": verdict, "topFactors": _top_factors(model, x),
            "modelVersion": _state.get("version"), "threshold": THRESHOLD}


def _unwrap(est):
    """Dig out the estimator that actually holds coef_/feature_importances_."""
    seen = 0
    while est is not None and seen < 5:
        seen += 1
        if hasattr(est, "coef_") or hasattr(est, "feature_importances_"):
            return est
        if isinstance(est, dict) and "model" in est:
            est = est["model"]
            continue
        if hasattr(est, "named_steps"):                 # Pipeline
            steps = list(est.named_steps.values())
            est = steps[-1] if steps else None
            continue
        if hasattr(est, "calibrated_classifiers_") and est.calibrated_classifiers_:
            inner = est.calibrated_classifiers_[0]
            est = getattr(inner, "estimator", None) or getattr(inner, "base_estimator", None)
            continue
        if hasattr(est, "estimator"):                   # CalibratedClassifierCV
            est = est.estimator
            continue
        break
    return est


def _top_factors(model, x) -> list:
    """Top contributing features (logistic regression coefficients)."""
    try:
        est = _unwrap(model)
        if est is None:
            return []
        if hasattr(est, "feature_importances_"):
            imp = est.feature_importances_
            return [{"feature": n, "contribution": round(float(v), 4)}
                    for n, v in sorted(zip(FEATURE_NAMES, imp), key=lambda t: -t[1])[:5]]
        coef = getattr(est, "coef_", None)
        if coef is None:
            return []
        try:
            import numpy as np
            flat = coef[0] if getattr(coef, "ndim", 1) > 1 else coef
        except Exception:
            flat = coef
        pairs = sorted(zip(FEATURE_NAMES, flat), key=lambda t: -abs(float(t[1])))
        return [{"feature": n, "contribution": round(float(v), 4)} for n, v in pairs[:5]]
    except Exception:
        return []
