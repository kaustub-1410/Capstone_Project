"""
Advanced Memory Stores — Experience replay, semantic memory, and episodic memory.

Extends the base memory system with ML-oriented memory structures for
reinforcement learning experience replay, semantic similarity search,
and timeline-based episodic recall.

Part of Phase 2: Agent Memory System.
"""

import logging
import random
from collections import deque
from datetime import datetime, timedelta
from typing import Any, Deque, Dict, List, Optional, Tuple

from agent_framework.memory import ExperienceEntry

logger = logging.getLogger(__name__)


class ExperienceReplayBuffer:
    """
    Prioritized experience replay buffer for RL-based agent learning.

    Stores (state, action, reward, next_state, done) tuples with
    priority-weighted sampling based on TD-error magnitude. Higher
    TD-error transitions are sampled more frequently.
    """

    def __init__(self, capacity: int = 10000, alpha: float = 0.6):
        """
        Args:
            capacity: Maximum buffer size before oldest entries are evicted.
            alpha: Priority exponent (0 = uniform, 1 = full prioritization).
        """
        self._capacity = capacity
        self._alpha = alpha
        self._buffer: Deque[Dict[str, Any]] = deque(maxlen=capacity)
        self._priorities: Deque[float] = deque(maxlen=capacity)
        self._max_priority: float = 1.0

    def add(
        self,
        state: Any,
        action: Any,
        reward: float,
        next_state: Any,
        done: bool,
        td_error: float = 1.0,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Add a transition to the replay buffer with optional priority."""
        entry = {
            "state": state,
            "action": action,
            "reward": reward,
            "next_state": next_state,
            "done": done,
            "metadata": metadata or {},
            "timestamp": datetime.utcnow().isoformat(),
        }
        priority = (abs(td_error) + 1e-6) ** self._alpha
        self._max_priority = max(self._max_priority, priority)
        self._buffer.append(entry)
        self._priorities.append(priority)

    def sample(self, batch_size: int = 32) -> List[Dict[str, Any]]:
        """
        Sample a batch of transitions with priority-weighted probabilities.

        Returns list of dicts with keys: state, action, reward, next_state,
        done, metadata, sampling_weight.
        """
        if len(self._buffer) == 0:
            return []

        n = min(batch_size, len(self._buffer))
        priorities = list(self._priorities)
        total_priority = sum(priorities)

        if total_priority == 0:
            # Uniform sampling fallback
            indices = random.sample(range(len(self._buffer)), n)
        else:
            # Weighted sampling
            probabilities = [p / total_priority for p in priorities]
            indices = random.choices(range(len(self._buffer)), weights=probabilities, k=n)

        batch = []
        for idx in indices:
            entry = dict(self._buffer[idx])
            # Importance sampling weight for bias correction
            prob = priorities[idx] / total_priority
            entry["sampling_weight"] = (1.0 / (len(self._buffer) * prob + 1e-8))
            batch.append(entry)

        return batch

    def update_priorities(self, indices: List[int], td_errors: List[float]) -> None:
        """Update priorities for sampled transitions after learning."""
        priorities_list = list(self._priorities)
        for idx, td_error in zip(indices, td_errors):
            if 0 <= idx < len(priorities_list):
                new_priority = (abs(td_error) + 1e-6) ** self._alpha
                priorities_list[idx] = new_priority
                self._max_priority = max(self._max_priority, new_priority)
        self._priorities = deque(priorities_list, maxlen=self._capacity)

    def __len__(self) -> int:
        return len(self._buffer)

    def is_ready(self, min_size: int = 64) -> bool:
        """Check if buffer has enough samples for training."""
        return len(self._buffer) >= min_size

    def clear(self) -> None:
        self._buffer.clear()
        self._priorities.clear()
        self._max_priority = 1.0


class SemanticMemory:
    """
    Semantic memory with vector similarity search over experiences.

    Supports encoding experiences into feature vectors and retrieving
    the most semantically similar past experiences given a query context.
    Uses a simple bag-of-words TF approach for offline operation;
    can be upgraded to transformer embeddings in production.
    """

    def __init__(self, embedding_dim: int = 64):
        self._entries: List[ExperienceEntry] = []
        self._vectors: List[List[float]] = []
        self._embedding_dim = embedding_dim
        self._vocabulary: Dict[str, int] = {}

    def store(self, entry: ExperienceEntry) -> None:
        """Store an experience with its computed embedding."""
        vector = self._encode(entry)
        self._entries.append(entry)
        self._vectors.append(vector)

    def search(self, query: ExperienceEntry, top_k: int = 5) -> List[Tuple[ExperienceEntry, float]]:
        """
        Find the top-k most similar experiences to the query.

        Returns list of (entry, similarity_score) tuples sorted by
        descending similarity.
        """
        if not self._entries:
            return []

        query_vector = self._encode(query)
        similarities = []

        for i, stored_vector in enumerate(self._vectors):
            sim = self._cosine_similarity(query_vector, stored_vector)
            similarities.append((i, sim))

        similarities.sort(key=lambda x: x[1], reverse=True)
        results = []
        for idx, sim in similarities[:top_k]:
            results.append((self._entries[idx], sim))

        return results

    def search_by_text(self, query_text: str, top_k: int = 5) -> List[Tuple[ExperienceEntry, float]]:
        """Search using a text query string."""
        # Create a synthetic entry from the query text
        synthetic = ExperienceEntry(
            agent_id="query",
            action=query_text,
            explanation=query_text,
        )
        return self.search(synthetic, top_k)

    def _encode(self, entry: ExperienceEntry) -> List[float]:
        """
        Encode an experience entry into a fixed-dimension vector.

        Uses a simple bag-of-words approach for offline compatibility.
        """
        # Build vocabulary from entry text fields
        text = f"{entry.action} {entry.target or ''} {entry.result} {entry.explanation}"
        tokens = text.lower().split()

        for token in tokens:
            if token not in self._vocabulary:
                if len(self._vocabulary) < self._embedding_dim:
                    self._vocabulary[token] = len(self._vocabulary)

        # Create sparse vector
        vector = [0.0] * self._embedding_dim
        for token in tokens:
            idx = self._vocabulary.get(token)
            if idx is not None and idx < self._embedding_dim:
                vector[idx] += 1.0

        # Normalize
        magnitude = sum(v ** 2 for v in vector) ** 0.5
        if magnitude > 0:
            vector = [v / magnitude for v in vector]

        return vector

    @staticmethod
    def _cosine_similarity(a: List[float], b: List[float]) -> float:
        """Compute cosine similarity between two vectors."""
        dot = sum(x * y for x, y in zip(a, b))
        mag_a = sum(x ** 2 for x in a) ** 0.5
        mag_b = sum(x ** 2 for x in b) ** 0.5
        if mag_a == 0 or mag_b == 0:
            return 0.0
        return dot / (mag_a * mag_b)

    def __len__(self) -> int:
        return len(self._entries)

    def clear(self) -> None:
        self._entries.clear()
        self._vectors.clear()
        self._vocabulary.clear()


class EpisodicMemory:
    """
    Timeline-based episodic memory for event recall.

    Stores experiences organized by episode (simulation run / incident),
    supporting temporal queries like "what happened before/after event X"
    and episode-level replay.
    """

    def __init__(self):
        self._episodes: Dict[str, List[ExperienceEntry]] = {}
        self._current_episode_id: Optional[str] = None
        self._timeline: List[ExperienceEntry] = []

    def start_episode(self, episode_id: str) -> None:
        """Begin a new episode for grouping experiences."""
        self._current_episode_id = episode_id
        if episode_id not in self._episodes:
            self._episodes[episode_id] = []
        logger.debug(f"Started episode: {episode_id}")

    def record(self, entry: ExperienceEntry) -> None:
        """Record an experience in the current episode and global timeline."""
        self._timeline.append(entry)
        if self._current_episode_id:
            self._episodes[self._current_episode_id].append(entry)

    def end_episode(self) -> Optional[str]:
        """End the current episode and return its ID."""
        episode_id = self._current_episode_id
        self._current_episode_id = None
        return episode_id

    def recall_episode(self, episode_id: str) -> List[ExperienceEntry]:
        """Retrieve all experiences from a specific episode."""
        return self._episodes.get(episode_id, [])

    def recall_before(
        self, timestamp: datetime, limit: int = 20
    ) -> List[ExperienceEntry]:
        """Recall experiences that occurred before a given timestamp."""
        before = [e for e in self._timeline if e.timestamp < timestamp]
        return before[-limit:]

    def recall_after(
        self, timestamp: datetime, limit: int = 20
    ) -> List[ExperienceEntry]:
        """Recall experiences that occurred after a given timestamp."""
        after = [e for e in self._timeline if e.timestamp > timestamp]
        return after[:limit]

    def recall_window(
        self, start: datetime, end: datetime
    ) -> List[ExperienceEntry]:
        """Recall experiences within a time window."""
        return [
            e for e in self._timeline
            if start <= e.timestamp <= end
        ]

    def recall_by_action(self, action: str) -> List[ExperienceEntry]:
        """Recall all experiences with a specific action across all episodes."""
        return [e for e in self._timeline if e.action == action]

    def recall_by_target(self, target: str) -> List[ExperienceEntry]:
        """Recall all experiences involving a specific target."""
        return [e for e in self._timeline if e.target == target]

    def get_episode_summary(self, episode_id: str) -> Dict[str, Any]:
        """Generate a summary of an episode."""
        entries = self._episodes.get(episode_id, [])
        if not entries:
            return {"episode_id": episode_id, "count": 0}

        actions = [e.action for e in entries]
        results = [e.result for e in entries]
        from collections import Counter
        action_counts = dict(Counter(actions))
        result_counts = dict(Counter(results))

        return {
            "episode_id": episode_id,
            "count": len(entries),
            "duration": (entries[-1].timestamp - entries[0].timestamp).total_seconds()
            if len(entries) > 1 else 0,
            "action_distribution": action_counts,
            "result_distribution": result_counts,
            "success_rate": result_counts.get("success", 0) / max(len(entries), 1),
            "avg_confidence": sum(e.confidence for e in entries) / len(entries),
        }

    def get_all_episode_ids(self) -> List[str]:
        """Return all episode IDs."""
        return list(self._episodes.keys())

    def __len__(self) -> int:
        return len(self._timeline)

    def clear(self) -> None:
        self._episodes.clear()
        self._timeline.clear()
        self._current_episode_id = None
