#!/usr/bin/env python3
"""Run all ensemble models on a directory of PE files and apply majority voting."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Iterable, List, Sequence

import joblib
import numpy as np
import pandas as pd

import pe_to_features
from ensemble_pipeline.aggregate_predictions import DEFAULT_MODELS
from ensemble_pipeline.common import extract_scores
from ensemble_vote import run_majority_voting
from classification_utils import CLASS_NAMES, summarize_classes

ROOT = Path(__file__).resolve().parent
DEFAULT_MODELS_DIR = ROOT / 'ensemble_models'
DEFAULT_MODEL_COLS = ROOT / 'model_columns.json'


def iter_pe_files(directory: Path) -> Iterable[Path]:
    for path in sorted(directory.iterdir()):
        if path.is_file():
            yield path


def load_model_columns(path: Path) -> List[str]:
    if not path.exists():
        raise FileNotFoundError(f'Missing feature column file: {path}')
    with open(path, 'r') as fh:
        cols = json.load(fh)
    if not isinstance(cols, list) or not cols:
        raise ValueError(f'Invalid column list in {path}')
    return cols


def extract_features(paths: Sequence[Path], model_cols: List[str]) -> pd.DataFrame:
    rows = []
    for idx, file_path in enumerate(paths):
        try:
            df = pe_to_features.to_features(file_path, model_cols)
        except Exception as exc:  # pragma: no cover - continue after logging
            print(f"[!] Failed to extract features from {file_path}: {exc}")
            continue
        if df.empty:
            continue
        row = df.iloc[0].copy()
        row['sample_index'] = idx
        row['sample_name'] = file_path.name
        row['sample_path'] = str(file_path)
        rows.append(row)
    if not rows:
        raise RuntimeError('No features were extracted from the directory.')
    return pd.DataFrame(rows)


def prepare_feature_matrix(df: pd.DataFrame, model_cols: List[str]) -> np.ndarray:
    for col in model_cols:
        if col not in df.columns:
            df[col] = 0
    feature_df = df[model_cols].apply(pd.to_numeric, errors='coerce').fillna(0)
    return feature_df.values


def run_models(feature_matrix: np.ndarray, model_names: Sequence[str], models_dir: Path) -> pd.DataFrame:
    predictions = pd.DataFrame({
        'sample_index': np.arange(feature_matrix.shape[0], dtype=int),
        'true_label': np.nan,
    })
    for name in model_names:
        model_path = models_dir / f'{name}.joblib'
        if not model_path.exists():
            raise FileNotFoundError(f'Missing model file: {model_path}')
        model = joblib.load(model_path)
        preds = model.predict(feature_matrix)
        scores = extract_scores(model, feature_matrix)
        predictions[f'{name}_pred'] = preds
        if scores is not None:
            predictions[f'{name}_score'] = scores
    return predictions


def build_output_df(meta_df: pd.DataFrame, voting_df: pd.DataFrame) -> pd.DataFrame:
    merged = voting_df.merge(meta_df[['sample_index', 'sample_name', 'sample_path']], on='sample_index', how='left')
    # reorder columns for readability
    columns = ['sample_index', 'sample_name', 'sample_path', 'votes_benign', 'votes_malware', 'ensemble_label']
    if 'ensemble_score' in merged.columns:
        columns.append('ensemble_score')
    columns.extend([c for c in merged.columns if c not in columns and not c.endswith('_pred') and not c.endswith('_score')])
    # include individual model predictions at the end for transparency
    model_cols = sorted([
        c for c in merged.columns
        if (c.endswith('_pred') or c.endswith('_score')) and c not in columns
    ])
    final_cols = columns + model_cols
    return merged[final_cols]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Apply ensemble voting to every PE inside a directory.')
    parser.add_argument('input_dir', type=Path, help='Directory of PE files to scan')
    parser.add_argument('--output', type=Path, help='Where to write the voting CSV (default: <folder>_voting_result.csv)')
    parser.add_argument('--models-dir', type=Path, default=DEFAULT_MODELS_DIR, help='Directory holding trained ensemble models')
    parser.add_argument('--model-columns', type=Path, default=DEFAULT_MODEL_COLS, help='Path to model_columns.json')
    parser.add_argument('--models', nargs='*', default=DEFAULT_MODELS, help='Specific model names to use (default: all)')
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    input_dir = args.input_dir.resolve()
    if not input_dir.is_dir():
        raise NotADirectoryError(f'{input_dir} is not a directory')

    files = list(iter_pe_files(input_dir))
    if not files:
        raise RuntimeError(f'No files found in {input_dir}')

    model_cols = load_model_columns(args.model_columns.resolve())
    features_df = extract_features(files, model_cols)
    feature_matrix = prepare_feature_matrix(features_df, model_cols)

    predictions_df = run_models(feature_matrix, args.models, args.models_dir.resolve())
    voting_df, _ = run_majority_voting(predictions_df, args.models)
    output_df = build_output_df(features_df, voting_df)

    output_path = args.output if args.output else Path(f'{input_dir.name}_voting_result.csv')
    output_path = output_path.resolve()
    output_df.to_csv(output_path, index=False)

    counts = summarize_classes(output_df.get('ensemble_class', []))
    summary = ', '.join(f"{name}={counts.get(name, 0)}" for name in CLASS_NAMES)
    print(f'[+] Wrote {output_path} ({len(output_df)} rows) — {summary}')


if __name__ == '__main__':
    main()
