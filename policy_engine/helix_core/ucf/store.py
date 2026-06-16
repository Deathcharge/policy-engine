"""
Helix Core - UCF Store

Persistent storage for UCF metrics and history.
Write-through cache over Redis: in-memory dict is L1, Redis is L2.
Cross-worker safe — Redis is the source of truth for current metrics.
"""

import asyncio
import json
import logging

from .metrics import UCFMetrics

logger = logging.getLogger(__name__)

# Module-level singleton — one store per worker process
_ucf_store: "UCFStore | None" = None
_store_init_lock: asyncio.Lock | None = None


def _get_store_init_lock() -> asyncio.Lock:
    global _store_init_lock
    if _store_init_lock is None:
        _store_init_lock = asyncio.Lock()
    return _store_init_lock


async def get_ucf_store() -> "UCFStore":
    """Return the singleton UCFStore, creating it with Redis backing if available."""
    global _ucf_store
    if _ucf_store is not None:
        return _ucf_store
    async with _get_store_init_lock():
        redis = None
        try:
            from apps.backend.core.redis_client import get_redis

            redis = await get_redis()
        except Exception as e:
            logger.warning("UCFStore: Redis unavailable, falling back to in-memory only: %s", e)
        new_store = UCFStore(redis=redis)
        _ucf_store = new_store
        logger.info("UCFStore singleton created (redis=%s)", redis is not None)
        return new_store


_REDIS_PREFIX = "helix:ucf:metrics:"
_REDIS_HISTORY_PREFIX = "helix:ucf:history:"


class UCFStore:
    """
    Storage for per-agent UCF metrics and history.

    Write-through cache over Redis (comment: # Write-through cache over Redis).
    Falls back to in-memory only when Redis is unavailable.
    """

    def __init__(self, max_history: int = 1000, redis=None):
        self._metrics: dict[str, UCFMetrics] = {}
        self._history: dict[str, list[UCFMetrics]] = {}
        self._max_history = max_history
        self._store_lock = asyncio.Lock()
        self._redis = redis  # Write-through cache over Redis
        logger.info("UCFStore initialized (redis=%s)", redis is not None)

    async def get_metrics(self, agent_id: str) -> UCFMetrics | None:
        async with self._store_lock:
            if agent_id in self._metrics:
                return self._metrics[agent_id]
            # L2: Redis
            if self._redis is not None:
                try:
                    raw = await self._redis.get(f"{_REDIS_PREFIX}{agent_id}")
                    if raw:
                        m = UCFMetrics.from_dict(json.loads(raw))
                        self._metrics[agent_id] = m
                        return m
                except Exception as e:
                    logger.warning("UCFStore Redis read failed agent=%s: %s", agent_id, e)
            return None

    async def set_metrics(self, agent_id: str, metrics: UCFMetrics) -> None:
        async with self._store_lock:
            old = self._metrics.get(agent_id)
            if old is not None:
                self._history.setdefault(agent_id, []).append(old)
                hist = self._history[agent_id]
                if len(hist) > self._max_history:
                    self._history[agent_id] = hist[-self._max_history :]

            self._metrics[agent_id] = metrics.copy()

            if self._redis is not None:
                try:
                    pipe = self._redis.pipeline()
                    pipe.set(f"{_REDIS_PREFIX}{agent_id}", json.dumps(metrics.to_dict()))
                    if old is not None:
                        pipe.rpush(f"{_REDIS_HISTORY_PREFIX}{agent_id}", json.dumps(old.to_dict()))
                        pipe.ltrim(f"{_REDIS_HISTORY_PREFIX}{agent_id}", -self._max_history, -1)
                    await pipe.execute()
                except Exception as e:
                    logger.warning("UCFStore Redis write failed agent=%s: %s", agent_id, e)

        logger.debug("Stored metrics for agent %s", agent_id)

    async def get_history(self, agent_id: str, limit: int = 100) -> list[UCFMetrics]:
        async with self._store_lock:
            if agent_id in self._history:
                return self._history[agent_id][-limit:]
            # L2: Redis list
            if self._redis is not None:
                try:
                    raw_list = await self._redis.lrange(f"{_REDIS_HISTORY_PREFIX}{agent_id}", -limit, -1)
                    if raw_list:
                        return [UCFMetrics.from_dict(json.loads(r)) for r in raw_list]
                except Exception as e:
                    logger.warning("UCFStore Redis history read failed agent=%s: %s", agent_id, e)
            return []

    async def get_all_agents(self) -> list[str]:
        """Return all agent IDs with stored metrics (cross-worker via Redis scan)."""
        ids: set[str] = set(self._metrics.keys())
        if self._redis is not None:
            try:
                async for key in self._redis.scan_iter(f"{_REDIS_PREFIX}*"):
                    agent_id = key.removeprefix(_REDIS_PREFIX)
                    ids.add(agent_id)
            except Exception as e:
                logger.warning("UCFStore Redis scan failed: %s", e)
        return sorted(ids)

    async def delete_agent(self, agent_id: str) -> None:
        async with self._store_lock:
            self._metrics.pop(agent_id, None)
            self._history.pop(agent_id, None)
            if self._redis is not None:
                try:
                    await self._redis.delete(
                        f"{_REDIS_PREFIX}{agent_id}",
                        f"{_REDIS_HISTORY_PREFIX}{agent_id}",
                    )
                except Exception as e:
                    logger.warning("UCFStore Redis delete failed agent=%s: %s", agent_id, e)
        logger.debug("Deleted metrics for agent %s", agent_id)

    async def get_aggregate_metrics(self) -> dict[str, float]:
        """Aggregate UCF metrics across all tracked agents."""
        agents = await self.get_all_agents()
        if not agents:
            return {
                "harmony": 0.0,
                "resilience": 0.0,
                "throughput": 0.0,
                "focus": 0.0,
                "friction": 0.0,
                "velocity": 0.0,
                "count": 0,
            }
        metrics: list[UCFMetrics] = []
        for agent_id in agents:
            m = await self.get_metrics(agent_id)
            if m is not None:
                metrics.append(m)
        if not metrics:
            return {
                "harmony": 0.0,
                "resilience": 0.0,
                "throughput": 0.0,
                "focus": 0.0,
                "friction": 0.0,
                "velocity": 0.0,
                "count": 0,
            }
        n = len(metrics)
        return {
            "harmony": sum(m.harmony for m in metrics) / n,
            "resilience": sum(m.resilience for m in metrics) / n,
            "throughput": sum(m.throughput for m in metrics) / n,
            "focus": sum(m.focus for m in metrics) / n,
            "friction": sum(m.friction for m in metrics) / n,
            "velocity": sum(m.velocity for m in metrics) / n,
            "count": n,
        }

    async def export_to_dict(self) -> dict:
        agents = await self.get_all_agents()
        result: dict = {"metrics": {}, "history": {}}
        for agent_id in agents:
            m = await self.get_metrics(agent_id)
            if m:
                result["metrics"][agent_id] = m.to_dict()
            h = await self.get_history(agent_id)
            if h:
                result["history"][agent_id] = [e.to_dict() for e in h]
        return result

    async def import_from_dict(self, data: dict) -> None:
        for agent_id, metrics_data in data.get("metrics", {}).items():
            await self.set_metrics(agent_id, UCFMetrics.from_dict(metrics_data))
        logger.info("Imported UCF data for %d agents", len(data.get("metrics", {})))

    async def clear_all(self) -> None:
        async with self._store_lock:
            agent_ids = list(self._metrics.keys())
            self._metrics.clear()
            self._history.clear()
        if self._redis is not None:
            try:
                keys = [f"{_REDIS_PREFIX}{a}" for a in agent_ids]
                keys += [f"{_REDIS_HISTORY_PREFIX}{a}" for a in agent_ids]
                if keys:
                    await self._redis.delete(*keys)
            except Exception as e:
                logger.warning("UCFStore Redis clear failed: %s", e)
        logger.info("Cleared all UCF store data")
