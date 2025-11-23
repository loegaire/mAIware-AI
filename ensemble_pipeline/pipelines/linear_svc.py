#!/usr/bin/env python3
"""Train the linear SVC ensemble model."""
from __future__ import annotations

from sklearn.svm import LinearSVC

from ensemble_pipeline.common import (RANDOM_STATE, linear_pipeline,
                                      make_common_parser, run_model_pipeline)

MODEL_NAME = 'linear_svc'


def build_estimator() -> LinearSVC:
    return linear_pipeline(
        LinearSVC(
            C=1.0,
            class_weight='balanced',
            dual=False,
            max_iter=5000,
            random_state=RANDOM_STATE,
        )
    )


def parse_args():
    return make_common_parser('Train the linear SVC ensemble model.').parse_args()


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
