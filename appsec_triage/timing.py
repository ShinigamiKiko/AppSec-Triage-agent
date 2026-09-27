"""Seconds a finding spends per kind of work, added up from wherever that work runs.

A finding's time goes to the model, the language server, Psalm and to waiting for
Psalm, several of them at once when its questions run side by side. The pipeline opens
a collection per finding; the code doing the work only says what kind it is. The sums
of work done in parallel can exceed the finding's total.
"""

from __future__ import annotations

import contextvars
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import TypeVar

_CURRENT: contextvars.ContextVar[dict[str, float] | None] = contextvars.ContextVar(
    "appsec_timings", default=None)
_LOCK = threading.Lock()
T = TypeVar("T")


@contextmanager
def collecting(timings: dict[str, float]) -> Iterator[dict[str, float]]:
    """Add the time measured inside, in this thread and in the ones it `carry`s to, to `timings`."""
    token = _CURRENT.set(timings)
    try:
        yield timings
    finally:
        _CURRENT.reset(token)


def add(kind: str, seconds: float) -> None:
    timings = _CURRENT.get()
    if timings is None or seconds <= 0:
        return
    with _LOCK:
        timings[kind] = timings.get(kind, 0.0) + seconds


@contextmanager
def measure(kind: str) -> Iterator[None]:
    started = time.monotonic()
    try:
        yield
    finally:
        add(kind, time.monotonic() - started)


def carry(function: Callable[..., T]) -> Callable[..., T]:
    """`function` for a worker thread, its time added to the finding that handed it over."""
    timings = _CURRENT.get()
    if timings is None:
        return function

    def run(*args, **kwargs):
        token = _CURRENT.set(timings)
        try:
            return function(*args, **kwargs)
        finally:
            _CURRENT.reset(token)

    return run
