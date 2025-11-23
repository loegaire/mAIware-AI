#!/usr/bin/env python3
"""Train the SGD logistic regression ensemble model."""
from __future__ import annotations

from sklearn.linear_model import SGDClassifier

from ensemble_pipeline.common import (RANDOM_STATE, linear_pipeline,
                                      make_common_parser, run_model_pipeline)

MODEL_NAME = 'sgd_logistic'


def build_estimator() -> SGDClassifier:
    return linear_pipeline(
        SGDClassifier(
            loss='log_loss',
            penalty='l2',
            max_iter=3000,
            learning_rate='optimal',
            class_weight='balanced',
            random_state=RANDOM_STATE,
        )
    )


def parse_args():
    return make_common_parser('Train the SGD logistic ensemble model.').parse_args()


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
