"""Circuit breaker (để lại cho dùng nội bộ; không còn outbound call trong forensic mode).

Why: an external provider that starts failing must not turn into a latency
bomb for our own requests. With a breaker the 4th consecutive failure opens the
circuit, every following call fails instantly with `CircuitOpen` and the
caller degrades gracefully ("unknown" / "unavailable") instead of waiting for
timeouts.

States: closed (normal) -> open (failing fast) -> half_open (thử 1 lần) -> ...
Env: BREAKER_FAIL_THRESHOLD (5), BREAKER_RESET_SECONDS (60).
"""
import os
import threading
import time


class CircuitOpen(Exception):
    """Raised when the breaker is open — the caller must degrade gracefully."""


class Breaker:
    def __init__(self, name: str, fail_threshold: int = 0, reset_after: int = 0):
        self.name = name
        self.fail_threshold = fail_threshold or int(os.getenv("BREAKER_FAIL_THRESHOLD", "5") or 5)
        self.reset_after = reset_after or int(os.getenv("BREAKER_RESET_SECONDS", "60") or 60)
        self._lock = threading.Lock()
        self._fails = 0
        self._opened_at = 0.0
        self._half_open = False
        self.trips = 0          # how many times the breaker opened
        self.last_error = ""

    # --- state -----------------------------------------------------------
    def state(self) -> str:
        with self._lock:
            if not self._opened_at:
                return "closed"
            if time.time() - self._opened_at >= self.reset_after:
                return "half_open"
            return "open"

    def _enter(self) -> None:
        """Caller may proceed (closed, or half_open probe)."""
        with self._lock:
            if not self._opened_at:
                return
            if time.time() - self._opened_at >= self.reset_after:
                self._half_open = True
                return
            raise CircuitOpen(self.name)

    # --- feedback --------------------------------------------------------
    def ok(self) -> None:
        with self._lock:
            self._fails = 0
            self._opened_at = 0.0
            self._half_open = False

    def fail(self, err: str = "") -> None:
        with self._lock:
            self._fails += 1
            self.last_error = str(err)[:200]
            if self._half_open or self._fails >= self.fail_threshold:
                if not self._opened_at:
                    self.trips += 1
                self._opened_at = time.time()
                self._half_open = False

    # --- helper ----------------------------------------------------------
    def call(self, fn, *args, **kwargs):
        """Run fn() through the breaker. Raises CircuitOpen when open."""
        self._enter()
        try:
            out = fn(*args, **kwargs)
        except Exception as e:
            self.fail(f"{type(e).__name__}: {e}")
            raise
        self.ok()
        return out


_REGISTRY = {}
_REG_LOCK = threading.Lock()


def get_breaker(name: str) -> Breaker:
    with _REG_LOCK:
        b = _REGISTRY.get(name)
        if b is None:
            b = Breaker(name)
            _REGISTRY[name] = b
        return b


def snapshot() -> dict:
    """State of every breaker — for /api/health?deep=1."""
    with _REG_LOCK:
        return {name: {"state": b.state(), "fails": b._fails, "trips": b.trips,
                       "lastError": b.last_error} for name, b in _REGISTRY.items()}
