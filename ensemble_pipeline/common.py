#!/usr/bin/env python3
"""Shared helpers for ensemble training pipelines."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Dict, List, Sequence, Tuple

import joblib
import numpy as np
import pandas as pd
from sklearn.base import BaseEstimator, clone
from sklearn.metrics import (accuracy_score, f1_score, precision_score,
                             recall_score, roc_auc_score)
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

ROOT = Path(__file__).resolve().parent.parent
MODEL_COLUMNS_PATH = ROOT / 'model_columns.json'
TRAIN_FILES = [ROOT / 'benign_train_no_meta.csv', ROOT / 'malware_train_no_meta.csv']
TEST_FILES = [ROOT / 'benign_test_no_meta.csv', ROOT / 'malware_test_no_meta.csv']
RANDOM_STATE = 42
N_JOBS = -1


Dataset = Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray, List[str]]

def make_common_parser(description: str) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument('--models-dir', type=Path, default=ROOT / 'ensemble_models', help='Directory for serialized models')
    parser.add_argument('--results-dir', type=Path, default=ROOT / 'ensemble_results', help='Directory for per-model outputs')
    parser.add_argument('--force-retrain', action='store_true', help='Retrain the model even if a cached version exists')
    return parser


def linear_pipeline(estimator: BaseEstimator) -> Pipeline:
    return Pipeline([
        ('scaler', StandardScaler()),
        ('clf', estimator),
    ])


def _read_and_label(path: Path, label: int) -> pd.DataFrame:
    df = pd.read_csv(path, low_memory=False)
    df['label'] = label
    return df


def _prepare_df(df: pd.DataFrame) -> pd.DataFrame:
    for c in df.columns:
        if c == 'label':
            continue
        df[c] = pd.to_numeric(df[c], errors='coerce')
    return df.fillna(0)


def load_dataset() -> Dataset:
    train_parts = []
    for path in TRAIN_FILES:
        if not path.exists():
            raise FileNotFoundError(f"Missing train file: {path}")
        label = 0 if 'benign' in path.name else 1
        train_parts.append(_read_and_label(path, label))

    test_parts = []
    for path in TEST_FILES:
        if not path.exists():
            raise FileNotFoundError(f"Missing test file: {path}")
        label = 0 if 'benign' in path.name else 1
        test_parts.append(_read_and_label(path, label))

    train_df = _prepare_df(pd.concat(train_parts, ignore_index=True))
    test_df = _prepare_df(pd.concat(test_parts, ignore_index=True))

    feature_columns = _determine_feature_columns(train_df)
    X_train = train_df[feature_columns].values
    y_train = train_df['label'].values
    X_test = test_df[feature_columns].values
    y_test = test_df['label'].values
    return X_train, y_train, X_test, y_test, feature_columns


def _determine_feature_columns(train_df: pd.DataFrame) -> List[str]:
    """Return the ordered feature column list used for training/inference."""
    default_columns = [c for c in train_df.columns if c != 'label']
    if not MODEL_COLUMNS_PATH.exists():
        return default_columns

    try:
        with open(MODEL_COLUMNS_PATH, 'r') as fh:
            desired_columns = json.load(fh)
    except Exception:
        return default_columns

    filtered = [c for c in desired_columns if c in train_df.columns]
    missing = [c for c in desired_columns if c not in train_df.columns]

    if not filtered:
        return default_columns

    if missing:
        print(f"[!] Warning: {len(missing)} model_columns missing from training data: {missing[:5]}...")

    return filtered


def ensure_dirs(models_dir: Path, results_dir: Path) -> None:
    models_dir.mkdir(parents=True, exist_ok=True)
    results_dir.mkdir(parents=True, exist_ok=True)


def _sigmoid(x: np.ndarray) -> np.ndarray:
    return 1.0 / (1.0 + np.exp(-np.clip(x, -50, 50)))


def extract_scores(model: BaseEstimator, X: np.ndarray) -> np.ndarray | None:
    if hasattr(model, 'predict_proba'):
        proba = model.predict_proba(X)
        if proba.ndim == 2 and proba.shape[1] >= 2:
            return proba[:, 1]
    if hasattr(model, 'decision_function'):
        scores = model.decision_function(X)
        if isinstance(scores, list):
            scores = np.array(scores)
        if scores.ndim > 1:
            scores = scores[:, 1]
        return _sigmoid(scores.astype(float))
    return None


def compute_metrics(y_true: np.ndarray, y_pred: np.ndarray, scores: np.ndarray | None) -> Dict[str, float | None]:
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


def run_model_pipeline(
    model_name: str,
    estimator: BaseEstimator,
    models_dir: Path,
    results_dir: Path,
    force_retrain: bool = False,
    dataset: Dataset | None = None,
) -> Dict[str, float | None]:
    ensure_dirs(models_dir, results_dir)
    if dataset is None:
        dataset = load_dataset()
    X_train, y_train, X_test, y_test, _ = dataset

    model_path = models_dir / f'{model_name}.joblib'
    if model_path.exists() and not force_retrain:
        print(f'[+] Loading cached model {model_name} from {model_path}')
        model = joblib.load(model_path)
    else:
        print(f'[+] Training model {model_name}')
        model = clone(estimator)
        model.fit(X_train, y_train)
        joblib.dump(model, model_path)
        print(f'    Saved to {model_path}')

    y_pred = model.predict(X_test)
    scores = extract_scores(model, X_test)
    metrics = compute_metrics(y_test, y_pred, scores)

    predictions = {
        'sample_index': np.arange(len(y_test)),
        'true_label': y_test,
        f'{model_name}_pred': y_pred,
    }
    if scores is not None:
        predictions[f'{model_name}_score'] = scores

    predictions_df = pd.DataFrame(predictions)
    predictions_path = results_dir / f'{model_name}_predictions.csv'
    predictions_df.to_csv(predictions_path, index=False)

    metrics_path = results_dir / f'{model_name}_metrics.json'
    with open(metrics_path, 'w') as fh:
        json.dump(metrics, fh, indent=2)

    print('[+] Wrote outputs:')
    print(f'    - {model_path}')
    print(f'    - {predictions_path}')
    print(f'    - {metrics_path}')

    return metrics


def merge_prediction_files(
    model_names: Sequence[str],
    results_dir: Path,
    output_path: Path | None = None,
) -> Path:
    if output_path is None:
        output_path = results_dir / 'model_predictions.csv'

    merged_df: pd.DataFrame | None = None
    for name in model_names:
        path = results_dir / f'{name}_predictions.csv'
        if not path.exists():
            raise FileNotFoundError(f'Missing prediction file for {name}: {path}')
        df = pd.read_csv(path)
        cols_to_use = [c for c in df.columns if c not in {'sample_index', 'true_label'}]
        if merged_df is None:
            merged_df = df
        else:
            merged_df = merged_df.merge(df[['sample_index', *cols_to_use]], on='sample_index', how='inner')
    assert merged_df is not None, 'No prediction files merged.'
    merged_df.to_csv(output_path, index=False)
    print(f'[+] Wrote merged predictions to {output_path}')
    return output_path


def aggregate_metrics(
    model_names: Sequence[str],
    results_dir: Path,
    output_path: Path | None = None,
) -> Path:
    metrics: Dict[str, Dict[str, float | None]] = {}
    for name in model_names:
        path = results_dir / f'{name}_metrics.json'
        if not path.exists():
            raise FileNotFoundError(f'Missing metrics file for {name}: {path}')
        with open(path, 'r') as fh:
            metrics[name] = json.load(fh)

    if output_path is None:
        output_path = results_dir / 'model_metrics.json'
    with open(output_path, 'w') as fh:
        json.dump(metrics, fh, indent=2)
    print(f'[+] Wrote aggregated metrics to {output_path}')
    return output_path
