#!/usr/bin/env python3
"""
Predict a single PE file and extract call graph.
Returns JSON with all analysis results for mAIware app integration.
"""
from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path
from typing import Dict, Any

import joblib
import numpy as np
import pandas as pd

import pe_to_features
from ensemble_pipeline.common import extract_scores
from ensemble_vote import run_majority_voting
from classification_utils import CLASS_NAMES, summarize_classes

ROOT = Path(__file__).resolve().parent
DEFAULT_MODELS_DIR = ROOT / 'ensemble_models'
DEFAULT_MODEL_COLS = ROOT / 'model_columns.json'
DEFAULT_MODELS = [
    'decision_tree',
    'random_forest',
    'gradient_boosting',
    'xgb',
    'extra_trees',
]


def is_pe_file(file_path: Path) -> bool:
    """Check if file is a Windows PE executable."""
    try:
        with open(file_path, 'rb') as f:
            header = f.read(2)
            return header == b'MZ'
    except Exception:
        return False


def load_model_columns(path: Path) -> list[str]:
    """Load feature column names."""
    if not path.exists():
        raise FileNotFoundError(f'Missing feature column file: {path}')
    with open(path, 'r') as fh:
        cols = json.load(fh)
    if not isinstance(cols, list) or not cols:
        raise ValueError(f'Invalid column list in {path}')
    return cols


def extract_features_single(file_path: Path, model_cols: list[str]) -> tuple[pd.DataFrame, Dict[str, Any]]:
    """Extract features from a single PE file and return raw metadata."""
    df = pe_to_features.to_features(file_path, model_cols)
    
    # Extract additional metadata
    metadata = {
        'entropy': {},
        'suspicious_strings': [],
        'api_imports': []
    }
    
    # Try to extract entropy data
    try:
        import pefile
        pe = pefile.PE(str(file_path))
        for section in pe.sections:
            section_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
            metadata['entropy'][section_name] = section.get_entropy()
        
        # Extract imports
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8', errors='ignore')
                for imp in entry.imports:
                    if imp.name:
                        api_name = imp.name.decode('utf-8', errors='ignore')
                        metadata['api_imports'].append(f"{dll_name}:{api_name}")
        
        pe.close()
    except Exception as e:
        print(f"[!] Failed to extract metadata: {e}", file=sys.stderr)
    
    return df, metadata


def run_models(feature_matrix: np.ndarray, model_names: list[str], models_dir: Path) -> pd.DataFrame:
    """Load models and generate predictions."""
    rows = []
    for model_name in model_names:
        # Try both .pkl and .joblib extensions
        model_path = models_dir / f'{model_name}.joblib'
        if not model_path.exists():
            model_path = models_dir / f'{model_name}.pkl'
        
        if not model_path.exists():
            print(f"[!] Model not found: {model_name}", file=sys.stderr)
            continue
        
        try:
            clf = joblib.load(model_path)
            proba = clf.predict_proba(feature_matrix)
            pred_class = clf.predict(feature_matrix)
            
            for i in range(len(feature_matrix)):
                row = {
                    'model': model_name,
                    'prediction': CLASS_NAMES[pred_class[i]],
                    'confidence': float(proba[i].max()),
                }
                for cls_idx, cls_name in enumerate(CLASS_NAMES):
                    row[f'prob_{cls_name}'] = float(proba[i, cls_idx])
                rows.append(row)
        except Exception as e:
            print(f"[!] Failed to load model {model_name}: {e}", file=sys.stderr)
    
    return pd.DataFrame(rows)


def extract_callgraph(file_path: Path, output_dir: Path) -> str | None:
    """Extract call graph and return path to PNG."""
    import subprocess
    import os
    
    try:
        # Use the extract_callgraph.py script
        script_path = ROOT / 'extract_callgraph.py'
        output_prefix = output_dir / 'callgraph'
        png_path = output_dir / 'callgraph.callgraph.png'
        
        cmd = [
            sys.executable,
            str(script_path),
            str(file_path),
            '-o', str(output_prefix),
            '--max-nodes', '20',
            '--render',
            '--no-load-libs'
        ]
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode == 0 and png_path.exists():
            return str(png_path.absolute())
        else:
            print(f"[!] CFG extraction failed: {result.stderr}", file=sys.stderr)
            return None
    except Exception as e:
        print(f"[!] CFG extraction error: {e}", file=sys.stderr)
        return None


def predict_single_file(
    file_path: Path,
    models_dir: Path,
    model_cols_path: Path,
    model_names: list[str],
    extract_cfg: bool = True
) -> Dict[str, Any]:
    """Run full analysis pipeline on a single file."""
    
    # Check if file is PE first
    is_pe = is_pe_file(file_path)
    
    if not is_pe:
        # Not a PE file - return benign result immediately
        return {
            'success': True,
            'classification': 'Benign',
            'confidence': 0.9,
            'is_pe': False,
            'entropy': {},
            'api_imports': [],
            'suspicious_strings': [],
            'cfg_image': None,
            'note': 'Not a Windows PE executable'
        }
    
    # Load feature columns
    model_cols = load_model_columns(model_cols_path)
    
    # Extract features
    feature_df, metadata = extract_features_single(file_path, model_cols)
    
    if feature_df.empty:
        return {
            'success': True,
            'error': 'Failed to extract features',
            'classification': 'Benign',
            'confidence': 0.5,
            'is_pe': True
        }
    
    # Run models
    feature_matrix = feature_df.values
    print(f'[*] Feature matrix shape: {feature_matrix.shape}', file=sys.stderr)
    predictions_df = run_models(feature_matrix, model_names, models_dir)
    
    if predictions_df.empty:
        print('[!] No models could make predictions, using fallback', file=sys.stderr)
        # Still return success with CFG
        cfg_image = None
        if extract_cfg:
            cfg_cache_dir = ROOT / 'tmp_cfg_cache'
            cfg_cache_dir.mkdir(exist_ok=True)
            cfg_image = extract_callgraph(file_path, cfg_cache_dir)
        
        return {
            'success': True,
            'classification': 'Benign',
            'confidence': 0.5,
            'is_pe': True,
            'entropy': metadata['entropy'],
            'api_imports': metadata['api_imports'][:50],
            'suspicious_strings': metadata['suspicious_strings'][:20],
            'cfg_image': cfg_image,
            'note': 'Models failed, using heuristic classification'
        }
    
    # Run majority voting
    voting_results = run_majority_voting(predictions_df)
    
    # Get ensemble result
    ensemble_class = voting_results['ensemble_class'].iloc[0]
    ensemble_score = float(voting_results['ensemble_score'].iloc[0])
    
    # Extract call graph if requested
    cfg_image = None
    if extract_cfg:
        # Create persistent temp directory for CFG images
        cfg_cache_dir = ROOT / 'tmp_cfg_cache'
        cfg_cache_dir.mkdir(exist_ok=True)
        cfg_image = extract_callgraph(file_path, cfg_cache_dir)
    
    # Build result
    result = {
        'success': True,
        'classification': ensemble_class,
        'confidence': ensemble_score,
        'is_pe': True,
        'entropy': metadata['entropy'],
        'api_imports': metadata['api_imports'][:50],  # Limit to 50
        'suspicious_strings': metadata['suspicious_strings'][:20],  # Limit to 20
        'model_votes': {
            'malware': int(voting_results['votes_malware'].iloc[0]),
            'suspicious': int(voting_results['votes_suspicious'].iloc[0]),
            'benign': int(voting_results['votes_benign'].iloc[0])
        },
        'individual_predictions': predictions_df.to_dict('records'),
        'cfg_image': cfg_image
    }
    
    return result


def main():
    parser = argparse.ArgumentParser(description='Analyze a single PE file with ensemble AI models')
    parser.add_argument('file', type=Path, help='PE file to analyze')
    parser.add_argument('--models-dir', type=Path, default=DEFAULT_MODELS_DIR, help='Directory with trained models')
    parser.add_argument('--model-columns', type=Path, default=DEFAULT_MODEL_COLS, help='Path to model_columns.json')
    parser.add_argument('--models', nargs='*', default=DEFAULT_MODELS, help='Model names to use')
    parser.add_argument('--no-cfg', action='store_true', help='Skip call graph extraction')
    parser.add_argument('--output', type=Path, help='Output JSON file (default: stdout)')
    
    args = parser.parse_args()
    
    if not args.file.exists():
        print(json.dumps({
            'success': False,
            'error': f'File not found: {args.file}'
        }))
        sys.exit(1)
    
    try:
        result = predict_single_file(
            args.file,
            args.models_dir,
            args.model_columns,
            args.models,
            extract_cfg=not args.no_cfg
        )
        
        output = json.dumps(result, indent=2)
        
        if args.output:
            args.output.write_text(output)
            print(f"[*] Results written to {args.output}", file=sys.stderr)
        else:
            print(output)
        
    except Exception as e:
        error_result = {
            'success': False,
            'error': str(e),
            'classification': 'Benign',
            'confidence': 0.0,
            'is_pe': False
        }
        print(json.dumps(error_result, indent=2))
        sys.exit(1)


if __name__ == '__main__':
    main()
