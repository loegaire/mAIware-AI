#!/usr/bin/env python3
"""Train the ExtraTrees ensemble model."""
from __future__ import annotations

from sklearn.ensemble import ExtraTreesClassifier

from ensemble_pipeline.common import N_JOBS, RANDOM_STATE, make_common_parser, run_model_pipeline

MODEL_NAME = 'extra_trees'


def build_estimator() -> ExtraTreesClassifier:
    return ExtraTreesClassifier(
        n_estimators=300,
        n_jobs=N_JOBS,
        class_weight='balanced',
        random_state=RANDOM_STATE,
    )


def parse_args():
    return make_common_parser('Train the ExtraTrees ensemble model.').parse_args()


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
