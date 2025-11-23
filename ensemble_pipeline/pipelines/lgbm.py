#!/usr/bin/env python3
"""Train a LightGBM classifier as part of the ensemble."""
from __future__ import annotations

try:
    from lightgbm import LGBMClassifier
except ImportError as exc:  # pragma: no cover - dependency guard
    raise ImportError(
        'lightgbm is required for the LGBM ensemble model. Install it via `pip install lightgbm`.'
    ) from exc

from ensemble_pipeline.common import make_common_parser, run_model_pipeline


MODEL_NAME = 'lgbm'


def build_estimator() -> LGBMClassifier:
    return LGBMClassifier(
        n_estimators=400,
        learning_rate=0.05,
        num_leaves=64,
        max_depth=-1,
        subsample=0.8,
        colsample_bytree=0.8,
        objective='binary',
        n_jobs=-1,
    )


def main() -> None:
    parser = make_common_parser('Train the LightGBM ensemble model.')
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
