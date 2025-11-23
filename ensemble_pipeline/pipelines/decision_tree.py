#!/usr/bin/env python3
"""Train the DecisionTree ensemble model."""
from __future__ import annotations

from sklearn.tree import DecisionTreeClassifier

from ensemble_pipeline.common import RANDOM_STATE, make_common_parser, run_model_pipeline

MODEL_NAME = 'decision_tree'


def build_estimator() -> DecisionTreeClassifier:
    return DecisionTreeClassifier(
        max_depth=50,
        min_samples_leaf=2,
        class_weight='balanced',
        random_state=RANDOM_STATE,
    )


def parse_args():
    return make_common_parser('Train the DecisionTree ensemble model.').parse_args()


def main() -> None:
    args = parse_args()
    run_model_pipeline(
        MODEL_NAME,
        build_estimator(),
        models_dir=args.models_dir,
        results_dir=args.results_dir,
        force_retrain=args.force_retrain,
    )


if __name__ == '__main__':
    main()
