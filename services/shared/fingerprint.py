from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any, Dict, List


_CITATION_PATTERNS = [
    r"\[[0-9]+\]",  # [1]
    r"\([A-Za-z]+,\s*\d{4}\)",  # (Smith, 2020)
    r"doi:\s*\S+",
]


def normalize_prompt(prompt: str) -> str:
    s = prompt.strip().lower()
    s = re.sub(r"\s+", " ", s)
    return s


def _prompt_intent_tags(prompt: str) -> List[str]:
    """Extract coarse, app-agnostic prompt 'shape' tags.

    Goal: prompts that *mean the same failure risk* should share tags even if the wording differs.
    This makes similarity deterministic for demo scenario 2.
    """

    p = normalize_prompt(prompt)
    tags: List[str] = []

    wants_citations = any(k in p for k in ["citation", "citations", "reference", "references", "sources", "bibliography"])
    if wants_citations:
        tags.append("intent:citations_required")

    # coarse task tags
    if any(k in p for k in ["summarize", "summary", "tl;dr"]):
        tags.append("task:summarization")
    if any(k in p for k in ["explain", "explanation", "describe"]):
        tags.append("task:explanation")

    # constraints
    if "even if not provided" in p or "even if none" in p:
        tags.append("constraint:no_sources_provided")
    if "include" in p and wants_citations:
        tags.append("instruction:include_references")

    return sorted(set(tags))


def signature_text(prompt: str, tools: List[str], env: Dict[str, Any]) -> str:
    # Intentionally app-agnostic: no app_id, no trace_id.
    tags = _prompt_intent_tags(prompt)
    # IMPORTANT (demo behavior):
    # Similarity search is TF-IDF over this string. To make "scenario 2" deterministic,
    # we keep the *stable intent tags* as the primary signal and keep prompt text short.
    pnorm = normalize_prompt(prompt)
    pshort = pnorm[:80]

    parts = [
        f"intent_tags:{','.join(tags)}",
        f"prompt_hint:{pshort}",
        f"tools:{','.join(sorted(set(tools)))}",
        f"env_keys:{','.join(sorted(env.keys()))}",
    ]
    return " | ".join(parts)


def fingerprint(prompt: str, tools: List[str], env: Dict[str, Any]) -> str:
    txt = signature_text(prompt, tools, env)
    return hashlib.sha256(txt.encode("utf-8")).hexdigest()[:16]


@dataclass(frozen=True)
class CitationCheck:
    has_citation_markers: bool


def detect_citation_markers(text: str) -> CitationCheck:
    t = text or ""
    for pat in _CITATION_PATTERNS:
        if re.search(pat, t):
            return CitationCheck(True)
    # crude heuristic: "References" section
    if "references" in t.lower() or "bibliography" in t.lower():
        return CitationCheck(True)
    return CitationCheck(False)
