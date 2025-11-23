#!/usr/bin/env python3
"""Train the logistic regression ensemble model."""
from __future__ import annotations

from sklearn.linear_model import LogisticRegression

from ensemble_pipeline.common import (RANDOM_STATE, linear_pipeline,
                                      make_common_parser, run_model_pipeline)


MODEL_NAME = 'log_reg'


def build_estimator() -> LogisticRegression:
    return linear_pipeline(
        LogisticRegression(
            max_iter=2000,
            solver='saga',
            penalty='l2',
            class_weight='balanced',
            random_state=RANDOM_STATE,
        )
    )


def parse_args():
    return make_common_parser('Train the logistic regression ensemble model.').parse_args()


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
