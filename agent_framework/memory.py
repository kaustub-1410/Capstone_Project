"""
Agent Memory System — Short-term, long-term memory, experience entries, and knowledge base.

Provides cognitive memory capabilities for all AMCDS agents. Supports offline
operation via in-memory/JSON storage and production deployment via PostgreSQL.

Part of Phase 1: Multi-Agent Society.
"""

import json
import logging
import os
import sqlite3
import uuid
from collections import deque
from datetime import datetime
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #
#  Data Models
# --------------------------------------------------------------------------- #

class ExperienceEntry(BaseModel):
    """A single recorded experience in agent memory."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    agent_id: str
    action: str
    target: Optional[str] = None
    result: str = "unknown"  # success, failed, partial, unknown
    confidence: float = 0.5
    context: Dict[str, Any] = Field(default_factory=dict)
    observation: Dict[str, Any] = Field(default_factory=dict)
    reward: float = 0.0
    explanation: str = ""

    class Config:
        json_encoders = {datetime: lambda v: v.isoformat()}


class KnowledgeFact(BaseModel):
    """A structured fact stored in the knowledge base."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    category: str  # host_state, credential, vulnerability, incident, tactic, relationship
    key: str
    value: Any
    confidence: float = 1.0
    source: str = "observation"  # observation, inference, intelligence, agent_report
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    ttl_seconds: Optional[float] = None  # Time-to-live; None = permanent


# --------------------------------------------------------------------------- #
#  Short-Term Memory
# --------------------------------------------------------------------------- #

class ShortTermMemory:
    """
    Rolling window of recent observations and actions.

    Implements a bounded deque that automatically evicts the oldest entries
    when capacity is reached. Designed for fast, in-context decision-making.
    """

    def __init__(self, capacity: int = 50):
        self._capacity = capacity
        self._buffer: Deque[ExperienceEntry] = deque(maxlen=capacity)
        logger.debug(f"ShortTermMemory initialized with capacity={capacity}")

    @property
    def capacity(self) -> int:
        return self._capacity

    def add(self, entry: ExperienceEntry) -> None:
        """Store a new experience entry."""
        self._buffer.append(entry)

    def get_recent(self, n: int = 10) -> List[ExperienceEntry]:
        """Retrieve the *n* most recent entries."""
        items = list(self._buffer)
        return items[-n:] if n < len(items) else items

    def get_by_action(self, action: str) -> List[ExperienceEntry]:
        """Filter entries by action type."""
        return [e for e in self._buffer if e.action == action]

    def get_by_target(self, target: str) -> List[ExperienceEntry]:
        """Filter entries referencing a specific target."""
        return [e for e in self._buffer if e.target == target]

    def get_successes(self) -> List[ExperienceEntry]:
        """Return only successful experiences."""
        return [e for e in self._buffer if e.result == "success"]

    def get_failures(self) -> List[ExperienceEntry]:
        """Return only failed experiences."""
        return [e for e in self._buffer if e.result == "failed"]

    def clear(self) -> None:
        self._buffer.clear()

    def __len__(self) -> int:
        return len(self._buffer)

    def to_summary(self, max_entries: int = 10) -> str:
        """Generate a textual summary suitable for LLM context injection."""
        recent = self.get_recent(max_entries)
        if not recent:
            return "No recent observations."
        lines = []
        for entry in recent:
            lines.append(
                f"[{entry.timestamp.strftime('%H:%M:%S')}] "
                f"Action={entry.action} Target={entry.target} "
                f"Result={entry.result} Confidence={entry.confidence:.2f}"
            )
        return "\n".join(lines)


# --------------------------------------------------------------------------- #
#  Long-Term Memory
# --------------------------------------------------------------------------- #

class LongTermMemory:
    """
    Persistent experience store with SQLite backend for offline use.

    Stores all historical experiences and supports filtered queries,
    statistical aggregations, and serialization for cross-session persistence.
    Can be swapped with a PostgreSQL backend for production deployment
    by replacing the storage adapter.
    """

    def __init__(self, agent_id: str, storage_dir: Optional[str] = None):
        self.agent_id = agent_id
        self._entries: List[ExperienceEntry] = []

        # SQLite persistence
        if storage_dir:
            self._storage_path = Path(storage_dir) / f"{agent_id}_memory.db"
        else:
            self._storage_path = Path(f".amcds_memory_{agent_id}.db")

        self._db_conn: Optional[sqlite3.Connection] = None
        self._init_storage()

    def _init_storage(self) -> None:
        """Initialize SQLite database for persistent memory."""
        try:
            self._storage_path.parent.mkdir(parents=True, exist_ok=True)
            self._db_conn = sqlite3.connect(str(self._storage_path))
            self._db_conn.execute("""
                CREATE TABLE IF NOT EXISTS experiences (
                    id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    target TEXT,
                    result TEXT DEFAULT 'unknown',
                    confidence REAL DEFAULT 0.5,
                    reward REAL DEFAULT 0.0,
                    explanation TEXT DEFAULT '',
                    context TEXT DEFAULT '{}',
                    observation TEXT DEFAULT '{}'
                )
            """)
            self._db_conn.commit()
            logger.debug(f"LongTermMemory storage initialized at {self._storage_path}")
        except Exception as e:
            logger.warning(f"Failed to initialize persistent storage: {e}. Using in-memory only.")
            self._db_conn = None

    def store(self, entry: ExperienceEntry) -> None:
        """Persist an experience entry to both in-memory list and SQLite."""
        self._entries.append(entry)

        if self._db_conn is not None:
            try:
                self._db_conn.execute(
                    """INSERT OR REPLACE INTO experiences
                       (id, timestamp, agent_id, action, target, result,
                        confidence, reward, explanation, context, observation)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        entry.id,
                        entry.timestamp.isoformat(),
                        entry.agent_id,
                        entry.action,
                        entry.target,
                        entry.result,
                        entry.confidence,
                        entry.reward,
                        entry.explanation,
                        json.dumps(entry.context, default=str),
                        json.dumps(entry.observation, default=str),
                    ),
                )
                self._db_conn.commit()
            except Exception as e:
                logger.error(f"Failed to persist experience to SQLite: {e}")

    def query(
        self,
        action: Optional[str] = None,
        target: Optional[str] = None,
        result: Optional[str] = None,
        min_confidence: float = 0.0,
        limit: int = 100,
    ) -> List[ExperienceEntry]:
        """Query stored experiences with optional filters."""
        filtered = self._entries
        if action:
            filtered = [e for e in filtered if e.action == action]
        if target:
            filtered = [e for e in filtered if e.target == target]
        if result:
            filtered = [e for e in filtered if e.result == result]
        if min_confidence > 0.0:
            filtered = [e for e in filtered if e.confidence >= min_confidence]
        return filtered[-limit:]

    def get_success_rate(self, action: Optional[str] = None) -> float:
        """Calculate success rate for a given action type (or overall)."""
        relevant = self._entries
        if action:
            relevant = [e for e in relevant if e.action == action]
        if not relevant:
            return 0.0
        successes = sum(1 for e in relevant if e.result == "success")
        return successes / len(relevant)

    def get_all(self) -> List[ExperienceEntry]:
        """Return all stored experiences."""
        return list(self._entries)

    def count(self) -> int:
        return len(self._entries)

    def load_from_storage(self) -> int:
        """Load persisted experiences from SQLite into memory."""
        if self._db_conn is None:
            return 0
        try:
            cursor = self._db_conn.execute(
                "SELECT id, timestamp, agent_id, action, target, result, "
                "confidence, reward, explanation, context, observation "
                "FROM experiences ORDER BY timestamp ASC"
            )
            loaded = 0
            for row in cursor.fetchall():
                entry = ExperienceEntry(
                    id=row[0],
                    timestamp=datetime.fromisoformat(row[1]),
                    agent_id=row[2],
                    action=row[3],
                    target=row[4],
                    result=row[5],
                    confidence=row[6],
                    reward=row[7],
                    explanation=row[8],
                    context=json.loads(row[9]) if row[9] else {},
                    observation=json.loads(row[10]) if row[10] else {},
                )
                self._entries.append(entry)
                loaded += 1
            logger.info(f"Loaded {loaded} experiences from persistent storage for agent {self.agent_id}")
            return loaded
        except Exception as e:
            logger.error(f"Failed to load from persistent storage: {e}")
            return 0

    def clear(self) -> None:
        """Clear both in-memory and persistent storage."""
        self._entries.clear()
        if self._db_conn is not None:
            try:
                self._db_conn.execute("DELETE FROM experiences")
                self._db_conn.commit()
            except Exception as e:
                logger.error(f"Failed to clear persistent storage: {e}")

    def close(self) -> None:
        """Close the database connection."""
        if self._db_conn is not None:
            self._db_conn.close()
            self._db_conn = None


# --------------------------------------------------------------------------- #
#  Knowledge Base
# --------------------------------------------------------------------------- #

class KnowledgeBase:
    """
    Structured facts store for an agent.

    Organizes knowledge by category (host_state, credential, vulnerability,
    incident, tactic, relationship) and supports fact assertion, retraction,
    querying, and confidence-weighted retrieval.
    """

    def __init__(self):
        self._facts: Dict[str, Dict[str, KnowledgeFact]] = {}

    def assert_fact(
        self,
        category: str,
        key: str,
        value: Any,
        confidence: float = 1.0,
        source: str = "observation",
        ttl_seconds: Optional[float] = None,
    ) -> KnowledgeFact:
        """Add or update a fact in the knowledge base."""
        fact = KnowledgeFact(
            category=category,
            key=key,
            value=value,
            confidence=confidence,
            source=source,
            ttl_seconds=ttl_seconds,
        )
        if category not in self._facts:
            self._facts[category] = {}
        self._facts[category][key] = fact
        return fact

    def retract_fact(self, category: str, key: str) -> bool:
        """Remove a fact from the knowledge base."""
        if category in self._facts and key in self._facts[category]:
            del self._facts[category][key]
            return True
        return False

    def get_fact(self, category: str, key: str) -> Optional[KnowledgeFact]:
        """Retrieve a specific fact."""
        cat = self._facts.get(category, {})
        fact = cat.get(key)
        if fact and fact.ttl_seconds is not None:
            elapsed = (datetime.utcnow() - fact.timestamp).total_seconds()
            if elapsed > fact.ttl_seconds:
                self.retract_fact(category, key)
                return None
        return fact

    def get_category(self, category: str) -> List[KnowledgeFact]:
        """Retrieve all facts in a category."""
        now = datetime.utcnow()
        results = []
        expired_keys = []
        for key, fact in self._facts.get(category, {}).items():
            if fact.ttl_seconds is not None:
                elapsed = (now - fact.timestamp).total_seconds()
                if elapsed > fact.ttl_seconds:
                    expired_keys.append(key)
                    continue
            results.append(fact)
        # Clean up expired facts
        for key in expired_keys:
            self.retract_fact(category, key)
        return results

    def get_all_facts(self) -> List[KnowledgeFact]:
        """Return every fact across all categories."""
        all_facts = []
        for category in list(self._facts.keys()):
            all_facts.extend(self.get_category(category))
        return all_facts

    def search(self, query: str) -> List[KnowledgeFact]:
        """Simple text search across fact keys and string values."""
        query_lower = query.lower()
        results = []
        for facts_dict in self._facts.values():
            for fact in facts_dict.values():
                if query_lower in fact.key.lower():
                    results.append(fact)
                elif isinstance(fact.value, str) and query_lower in fact.value.lower():
                    results.append(fact)
        return results

    def to_summary(self, max_facts: int = 20) -> str:
        """Generate a textual summary suitable for LLM context injection."""
        all_facts = self.get_all_facts()
        if not all_facts:
            return "No knowledge accumulated."
        lines = []
        for fact in all_facts[:max_facts]:
            lines.append(f"[{fact.category}] {fact.key} = {fact.value} (confidence={fact.confidence:.2f})")
        return "\n".join(lines)

    def clear(self) -> None:
        self._facts.clear()

    def fact_count(self) -> int:
        return sum(len(v) for v in self._facts.values())
