#!/usr/bin/env python3
"""Train an RBF-kernel SVM as part of the ensemble."""
from __future__ import annotations

from sklearn.svm import SVC

from ensemble_pipeline.common import linear_pipeline, make_common_parser, run_model_pipeline

MODEL_NAME = 'rbf_svm'


def build_estimator() -> SVC:
    base = SVC(kernel='rbf', C=3.0, gamma='scale', probability=True)
    return linear_pipeline(base)


def main() -> None:
    parser = make_common_parser('Train the RBF SVM ensemble model.')
    args = parser.parse_args()
    run_model_pipeline(
        MODEL_NAME,
        build_estimator(),
        models_dir=args.models_dir,
        results_dir=args.results_dir,
        force_retrain=args.force_retrain,
    )


if __name__ == '__main__':
    main()
