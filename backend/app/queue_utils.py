"""Helpers for bounded live-stream subscriber queues."""
from __future__ import annotations

import asyncio
from typing import Any


def offer_latest(queue: asyncio.Queue, item: Any) -> None:
    """Insert an item, dropping the oldest queued item when capacity is full."""
    while True:
        try:
            queue.put_nowait(item)
            return
        except asyncio.QueueFull:
            try:
                queue.get_nowait()
            except asyncio.QueueEmpty:
                continue