#!/usr/bin/env python3
"""Train the GaussianNB ensemble model."""
from __future__ import annotations

from sklearn.naive_bayes import GaussianNB

from ensemble_pipeline.common import make_common_parser, run_model_pipeline

MODEL_NAME = 'gaussian_nb'


def build_estimator() -> GaussianNB:
    return GaussianNB()


def parse_args():
    return make_common_parser('Train the GaussianNB ensemble model.').parse_args()


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
