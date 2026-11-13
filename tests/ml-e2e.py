"""End-to-end proof of the ML path: corpus -> features -> train -> verify -> server.

Uses a small SYNTHETIC labelled corpus (no download needed) so the whole
pipeline can be validated offline. Everything here also runs with a real
corpus (tools/build_features.py + tools/train_model.py).
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

p = f = 0


def ok(name, cond, extra=""):
    global p, f
    if cond:
        p += 1
        print("  PASS  " + name)
    else:
        f += 1
        print("  FAIL  " + name + ((" :: " + str(extra)[:250]) if extra else ""))


WORK = Path(tempfile.mkdtemp(prefix="ms-ml-e2e-"))
CORPUS = WORK / "corpus"
PHISH = CORPUS / "phishing"
BENIGN = CORPUS / "benign"
PHISH.mkdir(parents=True)
BENIGN.mkdir(parents=True)

PHISH_TMPL = """From: "IT Support" <support@paypa1-secure.com>
Return-Path: <bounce@evil-mailer.example>
Reply-To: <reset@another-bad.example>
Subject: URGENT verify your account password invoice payment
Received: from unknown (unknown [203.0.113.9]) by mx.local with ESMTP id {i}; Mon, 10 Nov 2026 10:00:00 +0000
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="B"

--B
Content-Type: text/html

<p>Click http://203.0.113.9/login.php to verify your account now</p>
--B
Content-Type: application/octet-stream; name="invoice.pdf.exe"
Content-Disposition: attachment; filename="invoice.pdf.exe"

X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
--B--
"""

BENIGN_TMPL = """From: {n} <{n}@example.org>
Return-Path: <{n}@example.org>
Subject: Meeting notes week {i}
Date: Mon, 10 Nov 2026 09:00:00 +0000
Received: from mail.example.org (mail.example.org [93.184.216.34]) by mx.local with ESMTP id b{i}; Mon, 10 Nov 2026 09:00:01 +0000
Content-Type: text/plain

Hi, here are the notes from our weekly sync. Let me know if anything is missing.
"""

N = 120
for i in range(N):
    (PHISH / f"p{i}.eml").write_text(PHISH_TMPL.replace("{i}", str(i)), encoding="utf-8")
    (BENIGN / f"b{i}.eml").write_text(
        BENIGN_TMPL.replace("{i}", str(i)).replace("{n}", f"user{i}"), encoding="utf-8")

print(f"[1] Corpus tá»•ng há»£p: {N} phishing + {N} benign")
feats = WORK / "features.jsonl"
r = subprocess.run([sys.executable, str(ROOT / "tools" / "build_features.py"),
                    "--corpus", str(CORPUS), "--out", str(feats)],
                   capture_output=True, text=True, encoding="utf-8", errors="replace", cwd=str(ROOT), timeout=900)
ok("build_features cháº¡y Ä‘Æ°á»£c", r.returncode == 0, (r.stdout + r.stderr)[-300:])
rows = [json.loads(x) for x in feats.read_text(encoding="utf-8").splitlines() if x.strip()]
ok("sinh Ä‘á»§ máº«u", len(rows) == 2 * N, len(rows))
ok("nhÃ£n Ä‘Ãºng (1=phishing, 0=benign)",
   sum(1 for x in rows if x["label"] == 1) == N and sum(1 for x in rows if x["label"] == 0) == N,
   (sum(1 for x in rows if x["label"] == 1), sum(1 for x in rows if x["label"] == 0)))
ok("má»—i máº«u cÃ³ Ä‘áº·c trÆ°ng", all(x["features"] for x in rows))
ok("khÃ´ng rÃ² ná»™i dung thÆ° trong máº«u",
   all("paypa1-secure" not in json.dumps(x["features"]) for x in rows))
ok("cÃ³ nhÃ³m nguá»“n Ä‘á»ƒ split theo nhÃ³m", len({x["source"] for x in rows}) >= 2,
   {x["source"] for x in rows})

print("\n[2] Train")
outdir = WORK / "models"
r = subprocess.run([sys.executable, str(ROOT / "tools" / "train_model.py"),
                    "--features", str(feats), "--out", str(outdir), "--model-type", "both", "--seed", "42"],
                   capture_output=True, text=True, encoding="utf-8", errors="replace", cwd=str(ROOT), timeout=1800)
print("   " + "\n   ".join((r.stdout or "").strip().splitlines()[-8:]))
ok("train thÃ nh cÃ´ng", r.returncode == 0, (r.stdout + r.stderr)[-400:])
ok("cÃ³ model.joblib", (outdir / "model.joblib").exists())
ok("cÃ³ model_card.json", (outdir / "model_card.json").exists())
ok("cÃ³ model_card.md", (outdir / "model_card.md").exists())
card = json.loads((outdir / "model_card.json").read_text(encoding="utf-8"))
ok("card cÃ³ metrics", "f1" in card.get("metrics", {}), list(card.get("metrics", {})))
ok("card cÃ³ confusion matrix", "confusionMatrix" in card.get("metrics", {}))
ok("card ghi nguá»“n + giáº¥y phÃ©p/hash", card.get("featuresSha256") and card.get("sources"))
ok("card ghi phiÃªn báº£n thÆ° viá»‡n", card.get("libraries", {}).get("scikit-learn"), card.get("libraries"))

print("\n[3] Verify (cá»•ng an toÃ n)")
r = subprocess.run([sys.executable, str(ROOT / "tools" / "verify_model.py"), str(outdir / "model.joblib")],
                   capture_output=True, text=True, encoding="utf-8", errors="replace", cwd=str(ROOT), timeout=300)
print("   " + (r.stdout or r.stderr).strip()[-400:])
ok("verify cháº¥p nháº­n model", r.returncode == 0, (r.stdout + r.stderr)[-300:])

print("\n[4] Server náº¡p model vÃ  cháº¥m Ä‘iá»ƒm (inference)")
os.environ["ML_ENABLED"] = "1"
os.environ["ML_MODEL_PATH"] = str(outdir / "model.joblib")
try:
    import importlib
    from app import ml as mlmod
    importlib.reload(mlmod)
    st = mlmod.status()
    ok("server tháº¥y model", st["state"] == "loaded", st)
    from app.main import feature_source
    from app.ml_features import extract_features
    # a phishing-like sample
    raw = (PHISH_TMPL.replace("{i}", "0")).encode()
    src = feature_source("p.eml", raw)
    out = mlmod.score_result(src)
    ok("model cháº¥m Ä‘Æ°á»£c (cÃ³ mlScore)", bool(out) and "mlScore" in out, out)
    ok("cho Ä‘iá»ƒm cao cho máº«u lá»«a Ä‘áº£o", out.get("mlScore", 0) >= 50, out)
    raw_b = (BENIGN_TMPL.replace("{i}", "0").replace("{n}", "user0")).encode()
    out_b = mlmod.score_result(feature_source("b.eml", raw_b))
    ok("cho Ä‘iá»ƒm tháº¥p cho máº«u sáº¡ch", out_b.get("mlScore", 100) <= 50, out_b)
    ok("cÃ³ topFactors Ä‘á»ƒ giáº£i thÃ­ch", len(out.get("topFactors") or []) > 0, out.get("topFactors"))
except Exception as e:
    ok("inference cháº¡y Ä‘Æ°á»£c", False, f"{type(e).__name__}: {e}")

print("\n[5] Model lá»‡ch schema bá»‹ tá»« chá»‘i")
try:
    from app import ml as mlmod
    importlib.reload(mlmod)
    bad = WORK / "bad"
    bad.mkdir(exist_ok=True)
    import joblib
    joblib.dump({"model": object(), "featureNames": ["wrong", "features"],
                 "meta": {"version": "x"}}, bad / "model.joblib")
    os.environ["ML_MODEL_PATH"] = str(bad / "model.joblib")
    importlib.reload(mlmod)          # the module reads the path at import time
    mlmod._loaded = False
    mlmod.load()
    out = mlmod.score_result({})
    ok("model sai schema -> khÃ´ng cháº¥m, khÃ´ng crash", out == {}, out)
    ok("tráº¡ng thÃ¡i bÃ¡o lá»—i", mlmod.status()["state"] in ("error", "absent"), mlmod.status())
finally:
    os.environ["ML_MODEL_PATH"] = str(outdir / "model.joblib")

shutil.rmtree(WORK, ignore_errors=True)
print(f"\n{p}/{p + f} PASS  (ML end-to-end)")
sys.exit(1 if f else 0)
