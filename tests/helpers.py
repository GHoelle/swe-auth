import threading


class FakeClock:
    """Lets tests jump forward in time instead of sleeping."""

    def __init__(self) -> None:
        self.start = 1_800_000_000.0
        self.now = self.start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds

    @property
    def elapsed(self) -> float:
        return self.now - self.start


class SpyHasher:
    """Wraps the real PasswordHasher and records verify() calls (it can't be monkeypatched)."""

    def __init__(self, real):
        self._real = real
        self.verify_calls: list[str] = []
        self.active = 0
        self.peak = 0
        self._lock = threading.Lock()

    def verify(self, stored_hash, password):
        with self._lock:
            self.verify_calls.append(stored_hash)
            self.active += 1
            self.peak = max(self.peak, self.active)
        try:
            return self._real.verify(stored_hash, password)
        finally:
            with self._lock:
                self.active -= 1

    def __getattr__(self, name):
        return getattr(self._real, name)
