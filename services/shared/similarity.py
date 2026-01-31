from __future__ import annotations

from dataclasses import dataclass
from typing import List

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity


@dataclass
class SimilarityEngine:
    """Embedding-ish similarity using TF-IDF for offline/air-gapped portability."""

    def score(self, query: str, corpus: List[str]) -> List[float]:
        if not corpus:
            return []
        vec = TfidfVectorizer(ngram_range=(1, 2), min_df=1)
        X = vec.fit_transform([query] + corpus)
        sims = cosine_similarity(X[0:1], X[1:]).flatten()
        return sims.tolist()
