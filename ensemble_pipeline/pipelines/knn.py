#!/usr/bin/env python3
"""Train the KNN ensemble model."""
from __future__ import annotations

from sklearn.neighbors import KNeighborsClassifier

from ensemble_pipeline.common import linear_pipeline, make_common_parser, run_model_pipeline

MODEL_NAME = 'knn'


def build_estimator() -> KNeighborsClassifier:
    return linear_pipeline(
        KNeighborsClassifier(n_neighbors=5, weights='distance')
    )


def parse_args():
    return make_common_parser('Train the KNN ensemble model.').parse_args()


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
