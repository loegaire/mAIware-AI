#!/usr/bin/env python3
"""Compute majority-vote predictions from stored per-model outputs."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Dict, List, Sequence

import numpy as np
import pandas as pd
from sklearn.metrics import (accuracy_score, f1_score, precision_score,
                             recall_score, roc_auc_score)

from classification_utils import (CLASS_NAMES, classify_prob_series,
                                  summarize_classes)

ROOT = Path('.').resolve()
DEFAULT_RESULTS_DIR = ROOT / 'ensemble_results'
DEFAULT_PREDICTIONS = DEFAULT_RESULTS_DIR / 'model_predictions.csv'


def _compute_metrics(y_true: np.ndarray | None, y_pred: np.ndarray, scores: np.ndarray | None) -> Dict[str, float | None]:
    if y_true is None or pd.isna(y_true).all():
        return {}

    metrics: Dict[str, float | None] = {
        'accuracy': float(accuracy_score(y_true, y_pred)),
        'precision': float(precision_score(y_true, y_pred, zero_division=0)),
        'recall': float(recall_score(y_true, y_pred, zero_division=0)),
        'f1': float(f1_score(y_true, y_pred, zero_division=0)),
    }
    if scores is not None:
        try:
            metrics['roc_auc'] = float(roc_auc_score(y_true, scores))
        except ValueError:
            metrics['roc_auc'] = None
    else:
        metrics['roc_auc'] = None
    return metrics


def _infer_model_names(predictions_df: pd.DataFrame) -> List[str]:
    model_names: List[str] = []
    for column in predictions_df.columns:
        if column in {'sample_index', 'true_label'}:
            continue
        if column.endswith('_pred'):
            model_names.append(column[:-5])
    if not model_names:
        raise ValueError('No *_pred columns were found in the predictions file.')
    return model_names


def run_majority_voting(
    predictions_df: pd.DataFrame,
    model_names: Sequence[str],
    *,
    true_label_column: str = 'true_label',
    sample_index_column: str = 'sample_index',
) -> tuple[pd.DataFrame, Dict[str, float | None]]:
    pred_cols = [f'{name}_pred' for name in model_names]
    pred_matrix = predictions_df[pred_cols].values
    votes_for_malware = pred_matrix.sum(axis=1)
    votes_for_benign = pred_matrix.shape[1] - votes_for_malware

    ensemble_pred = np.where(votes_for_malware > votes_for_benign, 1, 0)
    ties = votes_for_malware == votes_for_benign

    score_cols = [f'{name}_score' for name in model_names if f'{name}_score' in predictions_df.columns]
    avg_scores = None
    if score_cols:
        avg_scores = predictions_df[score_cols].mean(axis=1).to_numpy()

    if np.any(ties):
        if avg_scores is not None:
            ensemble_pred = np.where(ties, (avg_scores >= 0.5).astype(int), ensemble_pred)
        else:
            ensemble_pred = np.where(ties, 1, ensemble_pred)

    if sample_index_column in predictions_df.columns:
        sample_ids = predictions_df[sample_index_column]
    else:
        sample_ids = pd.Series(np.arange(len(predictions_df)), name='sample_index')

    if true_label_column in predictions_df.columns:
        true_labels = predictions_df[true_label_column]
    else:
        true_labels = pd.Series(np.nan, index=predictions_df.index, name='true_label')

    ensemble_df = pd.DataFrame({
        'sample_index': sample_ids,
        'true_label': true_labels,
        'votes_benign': votes_for_benign,
        'votes_malware': votes_for_malware,
        'ensemble_label': ensemble_pred,
    })
    if true_labels.notna().any():
        ensemble_df['correct'] = (ensemble_df['ensemble_label'] == true_labels).astype(int)
    if avg_scores is not None:
        ensemble_df['ensemble_score'] = avg_scores
    else:
        ensemble_df['ensemble_score'] = votes_for_malware / pred_matrix.shape[1]

    classes, class_ids = classify_prob_series(
        ensemble_df['ensemble_score'].tolist(),
        ensemble_df['ensemble_label'].tolist(),
    )
    ensemble_df['ensemble_class'] = classes
    ensemble_df['ensemble_class_id'] = class_ids

    y_true = ensemble_df['true_label'].to_numpy()
    ensemble_metrics = _compute_metrics(y_true, ensemble_df['ensemble_label'].to_numpy(), avg_scores)
    return ensemble_df, ensemble_metrics


def save_outputs(
    ensemble_df: pd.DataFrame,
    ensemble_metrics: Dict[str, float | None],
    results_dir: Path,
) -> None:
    results_dir.mkdir(parents=True, exist_ok=True)
    ensemble_path = results_dir / 'ensemble_vote_results.csv'
    ensemble_metrics_path = results_dir / 'ensemble_metrics.json'

    ensemble_df.to_csv(ensemble_path, index=False)
    with open(ensemble_metrics_path, 'w') as fh:
        json.dump(ensemble_metrics, fh, indent=2)

    print('[+] Wrote outputs:')
    print(f'    - {ensemble_path}')
    print(f'    - {ensemble_metrics_path}')


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Run majority voting on saved model predictions.')
    parser.add_argument('--predictions', type=Path, default=DEFAULT_PREDICTIONS,
                        help='CSV file produced by train_models with *_pred/ *_score columns')
    parser.add_argument('--results-dir', type=Path, default=DEFAULT_RESULTS_DIR,
                        help='Directory where ensemble_vote_results.csv will be written')
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if not args.predictions.exists():
        raise FileNotFoundError(
            f"Predictions file not found: {args.predictions}. Run ensemble_pipeline/train_models.py first."
        )

    predictions_df = pd.read_csv(args.predictions)
    model_names = _infer_model_names(predictions_df)
    ensemble_df, ensemble_metrics = run_majority_voting(predictions_df, model_names)
    save_outputs(ensemble_df, ensemble_metrics, args.results_dir)

    print('[*] Ensemble metrics:')
    for key, value in ensemble_metrics.items():
        print(f'    {key}: {value}')


if __name__ == '__main__':
    main()
