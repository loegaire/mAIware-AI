#!/usr/bin/env python3
"""Train an XGBoost classifier as part of the ensemble."""
from __future__ import annotations

try:
    from xgboost import XGBClassifier
except ImportError as exc:  # pragma: no cover - dependency guard
    raise ImportError('xgboost is required for the XGB ensemble model. Install it via `pip install xgboost`.') from exc

from ensemble_pipeline.common import make_common_parser, run_model_pipeline

MODEL_NAME = 'xgb'


def build_estimator() -> XGBClassifier:
    return XGBClassifier(
        n_estimators=300,
        learning_rate=0.05,
        max_depth=8,
        subsample=0.8,
        colsample_bytree=0.8,
        eval_metric='logloss',
        n_jobs=-1,
        use_label_encoder=False,
    )


def main() -> None:
    parser = make_common_parser('Train the XGBoost ensemble model.')
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
