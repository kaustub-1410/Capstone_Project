"""
Vector Store — Abstract and concrete implementations for vector similarity search.

Provides an abstract VectorStore interface with an in-memory NumPy-based
implementation for offline use. Can be extended with ChromaDB, FAISS,
or other vector database backends for production deployment.

Part of Phase 2: Agent Memory System.
"""

import logging
import math
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class VectorStore(ABC):
    """Abstract interface for vector similarity search backends."""

    @abstractmethod
    def add(self, id: str, vector: List[float], metadata: Optional[Dict[str, Any]] = None) -> None:
        """Add a vector with an ID and optional metadata."""
        pass

    @abstractmethod
    def search(self, query_vector: List[float], top_k: int = 5) -> List[Tuple[str, float, Dict[str, Any]]]:
        """Search for top-k most similar vectors. Returns (id, score, metadata) tuples."""
        pass

    @abstractmethod
    def delete(self, id: str) -> bool:
        """Delete a vector by ID."""
        pass

    @abstractmethod
    def count(self) -> int:
        """Return the number of stored vectors."""
        pass

    @abstractmethod
    def clear(self) -> None:
        """Remove all stored vectors."""
        pass


class InMemoryVectorStore(VectorStore):
    """
    In-memory vector store using pure Python cosine similarity.

    Suitable for offline operation and small-to-medium datasets
    (up to ~100k vectors). For larger datasets, use FAISS or ChromaDB.
    """

    def __init__(self, dimension: Optional[int] = None):
        """
        Args:
            dimension: Expected vector dimension. If None, inferred from first add.
        """
        self._dimension = dimension
        self._vectors: Dict[str, List[float]] = {}
        self._metadata: Dict[str, Dict[str, Any]] = {}
        self._norms: Dict[str, float] = {}

    def add(self, id: str, vector: List[float], metadata: Optional[Dict[str, Any]] = None) -> None:
        """Add a vector with an ID and optional metadata."""
        if self._dimension is None:
            self._dimension = len(vector)
        elif len(vector) != self._dimension:
            raise ValueError(
                f"Vector dimension mismatch: expected {self._dimension}, got {len(vector)}"
            )

        self._vectors[id] = vector
        self._metadata[id] = metadata or {}
        # Pre-compute norm for efficiency
        self._norms[id] = math.sqrt(sum(v * v for v in vector))

    def search(
        self, query_vector: List[float], top_k: int = 5
    ) -> List[Tuple[str, float, Dict[str, Any]]]:
        """
        Find the top-k most similar vectors using cosine similarity.

        Returns list of (id, similarity_score, metadata) tuples sorted
        by descending similarity.
        """
        if not self._vectors:
            return []

        query_norm = math.sqrt(sum(v * v for v in query_vector))
        if query_norm == 0:
            return []

        scores: List[Tuple[str, float]] = []
        for vec_id, vec in self._vectors.items():
            dot_product = sum(q * v for q, v in zip(query_vector, vec))
            vec_norm = self._norms.get(vec_id, 1.0)
            if vec_norm == 0:
                similarity = 0.0
            else:
                similarity = dot_product / (query_norm * vec_norm)
            scores.append((vec_id, similarity))

        scores.sort(key=lambda x: x[1], reverse=True)

        results = []
        for vec_id, sim in scores[:top_k]:
            results.append((vec_id, sim, self._metadata.get(vec_id, {})))

        return results

    def delete(self, id: str) -> bool:
        """Delete a vector by ID."""
        if id in self._vectors:
            del self._vectors[id]
            del self._metadata[id]
            del self._norms[id]
            return True
        return False

    def count(self) -> int:
        return len(self._vectors)

    def clear(self) -> None:
        self._vectors.clear()
        self._metadata.clear()
        self._norms.clear()

    def get_vector(self, id: str) -> Optional[List[float]]:
        """Retrieve a stored vector by ID."""
        return self._vectors.get(id)

    def get_metadata(self, id: str) -> Optional[Dict[str, Any]]:
        """Retrieve metadata for a stored vector."""
        return self._metadata.get(id)

    def get_all_ids(self) -> List[str]:
        """Return all stored vector IDs."""
        return list(self._vectors.keys())


class TextEmbedder:
    """
    Simple text embedder for converting text to fixed-dimension vectors.

    Uses a hashing-based approach for offline operation. Can be replaced
    with sentence-transformers or OpenAI embeddings in production.
    """

    def __init__(self, dimension: int = 128):
        self._dimension = dimension

    def embed(self, text: str) -> List[float]:
        """Convert text to a fixed-dimension vector using character-level hashing."""
        vector = [0.0] * self._dimension
        tokens = text.lower().split()

        for i, token in enumerate(tokens):
            # Hash each token to distribute across vector dimensions
            for j, char in enumerate(token):
                idx = (hash(token) + j * 31) % self._dimension
                vector[idx] += 1.0 / (i + 1)  # Position-weighted

        # L2 normalize
        magnitude = math.sqrt(sum(v * v for v in vector))
        if magnitude > 0:
            vector = [v / magnitude for v in vector]

        return vector

    def embed_batch(self, texts: List[str]) -> List[List[float]]:
        """Embed multiple texts."""
        return [self.embed(text) for text in texts]

    @property
    def dimension(self) -> int:
        return self._dimension
