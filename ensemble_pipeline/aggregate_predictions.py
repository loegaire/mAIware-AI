#!/usr/bin/env python3
"""Merge per-model prediction CSVs into model_predictions.csv."""
from __future__ import annotations

import argparse
from pathlib import Path

from ensemble_pipeline.common import ROOT, aggregate_metrics, merge_prediction_files

DEFAULT_MODELS = [
    'log_reg',
    'linear_svc',
    'sgd_logistic',
    'knn',
    'decision_tree',
    'random_forest',
    'extra_trees',
    'gradient_boosting',
    'ada_boost',
    'gaussian_nb',
    'lgbm',
    'rbf_svm',
    'xgb',
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Aggregate per-model prediction CSVs.')
    parser.add_argument('--results-dir', type=Path, default=ROOT / 'ensemble_results', help='Location of per-model prediction files')
    parser.add_argument('--models', nargs='*', default=DEFAULT_MODELS, help='Model names to include in the merge')
    parser.add_argument('--output', type=Path, default=None, help='Optional explicit output path for merged predictions')
    parser.add_argument('--skip-metrics', action='store_true', help='Do not rebuild model_metrics.json after merging')
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    merge_prediction_files(args.models, args.results_dir, args.output)
    if not args.skip_metrics:
        aggregate_metrics(args.models, args.results_dir)


if __name__ == '__main__':
    main()
