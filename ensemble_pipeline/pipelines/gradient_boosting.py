#!/usr/bin/env python3
"""Train the GradientBoosting ensemble model."""
from __future__ import annotations

from sklearn.ensemble import GradientBoostingClassifier

from ensemble_pipeline.common import RANDOM_STATE, make_common_parser, run_model_pipeline

MODEL_NAME = 'gradient_boosting'


def build_estimator() -> GradientBoostingClassifier:
    return GradientBoostingClassifier(
        learning_rate=0.05,
        n_estimators=300,
        subsample=0.8,
        random_state=RANDOM_STATE,
    )


def parse_args():
    return make_common_parser('Train the GradientBoosting ensemble model.').parse_args()


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
