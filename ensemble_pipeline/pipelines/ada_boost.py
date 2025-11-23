#!/usr/bin/env python3
"""Train the AdaBoost ensemble model."""
from __future__ import annotations

from sklearn.ensemble import AdaBoostClassifier

from ensemble_pipeline.common import RANDOM_STATE, make_common_parser, run_model_pipeline

MODEL_NAME = 'ada_boost'


def build_estimator() -> AdaBoostClassifier:
    return AdaBoostClassifier(
        n_estimators=300,
        learning_rate=0.5,
        random_state=RANDOM_STATE,
    )


def parse_args():
    return make_common_parser('Train the AdaBoost ensemble model.').parse_args()


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
