"""Offline tests for the new layers: circuit breaker, reputation, ML features.

No network access is required: the reputation providers are exercised through
mocked HTTP responses.
"""
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

# The reputation providers are mocked here -> the "live" switch must be on,
# otherwise enabled() short-circuits and no provider is ever called.
os.environ["LIVE_DNS"] = "1"

p = f = 0


def ok(name, cond, extra=""):
    global p, f
    if cond:
        p += 1
        print("  PASS  " + name)
    else:
        f += 1
        print("  FAIL  " + name + ((" :: " + str(extra)[:250]) if extra else ""))


print("[1] Circuit breaker")
from app.breaker import Breaker, CircuitOpen  # noqa: E402

b = Breaker("t", fail_threshold=3, reset_after=60)
ok("trạng thái ban đầu closed", b.state() == "closed", b.state())
for _ in range(3):
    try:
        b.call(lambda: (_ for _ in ()).throw(RuntimeError("boom")))
    except RuntimeError:
        pass
ok("sau 3 lỗi -> open", b.state() == "open", b.state())
try:
    b.call(lambda: "ok")
    ok("khi open thì raise CircuitOpen", False)
except CircuitOpen:
    ok("khi open thì raise CircuitOpen", True)
ok("số lần mở được đếm", b.trips == 1, b.trips)
b.reset_after = 0
b.call(lambda: "probe")
ok("half-open cho phép thử lại", b.state() in ("closed", "half_open"), b.state())

print("\n[2] Reputation — tắt mặc định, không gọi mạng")
os.environ["REPUTATION_ENABLED"] = "0"
from app import reputation  # noqa: E402

ok("mặc định tắt", reputation.enabled() is False)
r = reputation.check_url("http://evil.example/x")
ok("tắt -> verdict unknown", r["verdict"] == "unknown", r)
r = reputation.check_hash("a" * 64)
ok("hash tắt -> unknown", r["verdict"] == "unknown", r)

print("\n[3] Reputation — bật + mock provider")
os.environ["REPUTATION_ENABLED"] = "1"
os.environ["REPUTATION_CACHE_TTL"] = "60"


class FakeResp:
    def __init__(self, payload, code=200):
        self._p = payload
        self.status_code = code
        self.content = payload.encode()

    def json(self):
        import json as _j
        return _j.loads(self._p)


calls = {"n": 0}


def fake_post(url, data=None, json=None, headers=None, timeout=None, **kw):
    calls["n"] += 1
    if "urlhaus" in url:
        return FakeResp('{"query_status":"malicious","threat":"phishing","urlhaus_link":"https://x"}')
    if "safebrowsing" in url:
        return FakeResp('{"matches":[]}')
    return FakeResp("{}")


def fake_get(url, headers=None, timeout=None, **kw):
    calls["n"] += 1
    return FakeResp('{"data":{"attributes":{"last_analysis_stats":{"malicious":7,"suspicious":0}}}}')


class FakeRequests:
    post = staticmethod(fake_post)
    get = staticmethod(fake_get)


reputation._requests = lambda: FakeRequests()
reputation.clear_cache()
os.environ["ABUSECH_KEY"] = "test-key"
os.environ["VT_KEY"] = "test-key"
os.environ["SB_KEY"] = "test-key"
r = reputation.check_url("http://evil.example/x", "user1")
ok("URL bị liệt kê -> malicious", r["verdict"] == "malicious", r)
ok("có nguồn URLhaus", any(x["provider"] == "urlhaus" for x in r["providers"]), r["providers"])
ok("VirusTotal đếm 7 malicious", any("malicious=7" in str(x.get("detail")) for x in r["providers"]), r["providers"])
n_before = calls["n"]
r2 = reputation.check_url("http://evil.example/x", "user1")
ok("cache: lần 2 không gọi mại", calls["n"] == n_before, (n_before, calls["n"]))

print("\n[4] Reputation — thiếu key thì bỏ qua provider")
os.environ.pop("ABUSECH_KEY", None)
os.environ.pop("VT_KEY", None)
os.environ.pop("SB_KEY", None)
reputation.clear_cache()
r = reputation.check_url("http://x.example/y", "user1")
ok("không key -> không provider nào được gọi", r["providers"] == [], r["providers"])
ok("không key -> unknown", r["verdict"] == "unknown", r)

print("\n[5] Reputation — lỗi mạng không làm hỏng pipeline")
def boom_post(url, **kw):
    raise OSError("network down")


class FailRequests:
    post = staticmethod(boom_post)
    get = staticmethod(boom_post)


reputation._requests = lambda: FailRequests()
reputation.clear_cache()
os.environ["ABUSECH_KEY"] = "k"
r = reputation.check_url("http://x.example/y", "user1")
ok("lỗi mạng -> unknown, không raise", r["verdict"] == "unknown", r)
ok("lỗi mạng -> vẫn có bản ghi provider", len(r["providers"]) == 1, r["providers"])

print("\n[6] ML features — ổn định & không rò định danh")
from app.ml_features import FEATURE_NAMES, extract_features, feature_vector  # noqa: E402

ok("có tên đặc trưng", len(FEATURE_NAMES) >= 50, len(FEATURE_NAMES))
ok("không trùng tên", len(set(FEATURE_NAMES)) == len(FEATURE_NAMES))
sample = {
    "format": "eml", "count": 1, "score": 40, "verdict": "suspicious",
    "headerAnalysis": {"checks": [{"type": "from_returnpath_mismatch", "sev": 3, "weight": 10}],
                        "receivedCount": 4},
    "routing": {"hops": [{"ip": "1.2.3.4"}], "anomalies": [{"type": "routing_loop"}], "totalDelayMs": 500},
    "auth": {"spf": {"result": "fail"}, "dkim": {"result": "none"}, "dmarc": {"result": "fail"},
             "alignment": {"spf": False, "dkim": None}, "headerFound": True,
             "upstream": {"raw": "mx; spf=fail"}, "dkimSignatures": [{"domain": "x.com"}]},
    "urls": [{"url": "http://1.2.3.4/x", "host": "1.2.3.4", "risk": 90, "verdict": "malicious",
              "reasons": ["host is a raw IP address"]}],
    "attachments": [{"name": "a.exe", "verdict": "malicious", "reasons": ["EICAR antivirus test string detected"]}],
    "findings": [{"type": "phishing_url"}],
}
feats = extract_features(sample)
ok("trả đúng số đặc trưng", len(feats) == len(FEATURE_NAMES), (len(feats), len(FEATURE_NAMES)))
ok("vector đúng thứ tự", feature_vector(sample) == [float(feats[n]) for n in FEATURE_NAMES])
ok("bắt được mismatch header", feats["hdr_from_returnpath_mismatch"] == 1, feats["hdr_from_returnpath_mismatch"])
ok("bắt được URL IP-host", feats["url_ip_host"] == 1, feats["url_ip_host"])
ok("bắt được EICAR", feats["att_eicar"] == 1, feats["att_eicar"])
ok("bắt được ext nguy hiểm", feats["att_dangerous_ext"] == 1, feats["att_dangerous_ext"])
blob = repr(feats)
ok("không chứa URL/IP/brand thô",
   "1.2.3.4" not in blob and "a.exe" not in blob and "evil.example" not in blob, blob[:200])
ok("xử lý được result rỗng", len(extract_features({})) == len(FEATURE_NAMES))

print("\n[7] LLM — chặn bịa đặt (quote phải là chuỗi con)")
from app import llm  # noqa: E402

body = "Hóa đơn quá hạn, vui lòng thanh toán ngay."
ans = {"verdict": "phishing", "confidence": 0.9, "intent": "xin tiền",
       "evidence": [{"quote": "Hóa đơn quá hạn", "note": "lời nhắc đòi tiền"},
                    {"quote": "BÁO CÁO MẬT KHẨU", "note": "bịa"}],
       "actions": ["kiểm tra"]}
clean, good = llm._validate(ans, body)
ok("verdict hợp lệ", good and clean["verdict"] == "phishing", clean)
ok("giữ lại quote có thật", len(clean["evidence"]) == 1, clean["evidence"])
ok("loại bỏ quote bịa", all(e["quote"] in body for e in clean["evidence"]), clean["evidence"])
ans2 = {"verdict": "phishing", "confidence": 0.95, "evidence": [{"quote": "không có trong thư"}]}
clean2, good2 = llm._validate(ans2, body)
ok("kết luận mạnh không quote được -> hạ về suspicious",
   clean2["verdict"] == "suspicious" and clean2["confidence"] <= 0.5, clean2)
ok("verdict lạ bị từ chối", llm._validate({"verdict": "maybe"}, body)[1] is False)

print("\n[8] LLM — redaction")
red = llm._redact("mail admin@acme.vn từ 8.8.8.8 https://acme.vn/pay hãy chuyển 5.000.000đ")
ok("email che", "admin@acme.vn" not in red, red)
ok("IP che", "8.8.8.8" not in red, red)
ok("URL che", "acme.vn/pay" not in red, red)
ok("tiền và hành động còn lại", "5.000.000" in red, red)

print(f"\n{p}/{p + f} PASS  (layers mới)")
sys.exit(1 if f else 0)
