"""
AegisPilot - one way to open a URL, with retries for failures that are likely to pass.

A dropped connection, a TLS error or a registry that answers 429 / 5xx is retried here, with a pause between tries, so
the agent and the person are never told to "try again". A timeout is not retried (a slow server would only make the
person wait twice as long), nor is any other HTTP error (404 means the thing is not there). What still fails after the
last try is raised as before, and the caller records "could not check because ...".
"""
from __future__ import annotations

import socket
import ssl
import time
import urllib.error
import urllib.request

ATTEMPTS = 3                    # tries in all
PAUSES = (1.0, 3.0)             # seconds before the 2nd and the 3rd try
MAX_RETRY_AFTER = 5.0           # a registry's Retry-After is honored up to this


def _is_timeout(err: BaseException) -> bool:
    reason = getattr(err, "reason", err)
    return isinstance(reason, (socket.timeout, TimeoutError)) or "timed out" in str(reason).lower()


def retryable(err: BaseException) -> bool:
    """A failure worth another try: 429 / 5xx, a refused or dropped connection, a TLS error. Never a timeout."""
    if _is_timeout(err):
        return False
    if isinstance(err, urllib.error.HTTPError):
        return err.code == 429 or err.code >= 500
    return isinstance(err, (urllib.error.URLError, ConnectionError, ssl.SSLError))


def urlopen(req, timeout: float = 15, attempts: int = ATTEMPTS, sleep=time.sleep):
    """urllib.request.urlopen with the retries above; the response (or the last error) as urlopen gives it."""
    for i in range(attempts):
        try:
            return urllib.request.urlopen(req, timeout=timeout)
        except Exception as err:            # noqa: BLE001 - re-raised unless worth another try
            if i == attempts - 1 or not retryable(err):
                raise
            pause = PAUSES[min(i, len(PAUSES) - 1)]
            if isinstance(err, urllib.error.HTTPError):
                try:
                    pause = max(pause, min(MAX_RETRY_AFTER, float(err.headers.get("Retry-After") or 0)))
                except (TypeError, ValueError):
                    pass
            sleep(pause)
    raise RuntimeError("unreachable")
