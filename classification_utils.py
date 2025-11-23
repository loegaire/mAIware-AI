#!/usr/bin/env python3
"""Shared helpers for mapping malware probabilities to tri-state classes."""
from __future__ import annotations

from typing import Iterable, List, Sequence, Tuple

import math

BENIGN_MAX = 0.2
MALWARE_MIN = 0.6
CLASS_NAMES = ('benign', 'suspicious', 'malware')
CLASS_TO_ID = {name: idx for idx, name in enumerate(CLASS_NAMES)}


def classify_probability(prob: float | None, fallback_label: int | None = None,
                         benign_max: float = BENIGN_MAX,
                         malware_min: float = MALWARE_MIN) -> Tuple[str, int]:
    """Return (class_name, class_id) based on probability thresholds.

    If ``prob`` is None/NaN, fall back to the binary label if provided.
    """
    if prob is None or (isinstance(prob, float) and math.isnan(prob)):
        if fallback_label is None:
            return 'suspicious', CLASS_TO_ID['suspicious']
        name = 'malware' if fallback_label == 1 else 'benign'
        return name, CLASS_TO_ID[name]

    if prob <= benign_max:
        return 'benign', CLASS_TO_ID['benign']
    if prob >= malware_min:
        return 'malware', CLASS_TO_ID['malware']
    return 'suspicious', CLASS_TO_ID['suspicious']


def classify_prob_series(probs: Sequence[float | None],
                         fallback_labels: Sequence[int] | None = None,
                         benign_max: float = BENIGN_MAX,
                         malware_min: float = MALWARE_MIN) -> Tuple[List[str], List[int]]:
    names: List[str] = []
    ids: List[int] = []
    if fallback_labels is None:
        fallback_labels = [None] * len(probs)
    for prob, fallback in zip(probs, fallback_labels):
        name, idx = classify_probability(prob, fallback, benign_max, malware_min)
        names.append(name)
        ids.append(idx)
    return names, ids


def summarize_classes(class_names: Iterable[str]) -> dict[str, int]:
    counts: dict[str, int] = {name: 0 for name in CLASS_NAMES}
    counts.update({'unknown': 0})
    for name in class_names:
        if name in counts:
            counts[name] += 1
        else:
            counts['unknown'] += 1
    return counts
