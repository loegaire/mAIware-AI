#!/usr/bin/env python3
"""
Convert a PE file into a single-row CSV of features matching `model_columns.json`.

Usage:
  python3 pe_to_features.py input.exe out.csv

The script loads `model_columns.json` from the repo root to know which features to
produce. It will fill missing attributes with 0 and use simple heuristics for
fields like `Packed` and some LoadConfig fields if not available.

Requires: pefile
  pip install pefile
"""
import json
import math
import os
import sys
from collections import Counter
from pathlib import Path

import pefile
import pandas as pd


ROOT = Path(__file__).resolve().parent
MODEL_COLS = ROOT / 'model_columns.json'


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    probs = [c / len(data) for c in counts.values()]
    ent = -sum(p * math.log2(p) for p in probs if p > 0)
    return float(ent)


def count_resources(pe: pefile.PE) -> int:
    # Count resource data entries recursively
    def _count_entries(node):
        if hasattr(node, 'data'):
            return 1
        total = 0
        if hasattr(node, 'directory') and hasattr(node.directory, 'entries'):
            for e in node.directory.entries:
                total += _count_entries(e)
        elif hasattr(node, 'entries'):
            for e in node.entries:
                total += _count_entries(e)
        return total

    if not hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        return 0
    total = 0
    for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        total += _count_entries(entry)
    return total


def get_load_config_values(pe: pefile.PE):
    size = 0
    security_cookie = 0
    se_handler_table = 0
    try:
        lc = getattr(pe, 'DIRECTORY_ENTRY_LOAD_CONFIG', None)
        if lc is not None and hasattr(lc, 'struct'):
            struct = lc.struct
            size = int(getattr(struct, 'Size', 0) or 0)
            # SecurityCookie names vary by pefile version
            security_cookie = int(getattr(struct, 'SecurityCookie', 0) or getattr(struct, 'Security_cookie', 0) or 0)
            se_handler_table = int(getattr(struct, 'SEHandlerTable', 0) or getattr(struct, 'SEHandler_table', 0) or 0)
    except Exception:
        pass
    return size, security_cookie, se_handler_table


def to_features(path: Path, model_cols: list) -> pd.DataFrame:
    p = str(path)
    row = {c: 0 for c in model_cols}

    # File size
    try:
        row['FileSize'] = os.path.getsize(p)
    except Exception:
        row['FileSize'] = 0

    try:
        pe = pefile.PE(p, fast_load=True)
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT'],
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE'],
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_DEBUG'],
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_TLS'],
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG'],
        ])

        # entropy total (file-level)
        with open(p, 'rb') as fh:
            data = fh.read()
        row['Entropy_Total'] = entropy(data)

        # DOS header fields
        dos = pe.DOS_HEADER
        row['e_cp'] = int(getattr(dos, 'e_cp', 0) or 0)
        row['e_lfanew'] = int(getattr(dos, 'e_lfanew', 0) or 0)

        # IMAGE_FILE_HEADER / OPTIONAL_HEADER fields
        oh = pe.OPTIONAL_HEADER
        fhdr = pe.FILE_HEADER
        row['Machine'] = int(getattr(fhdr, 'Machine', 0) or 0)
        row['NumberOfSections'] = int(getattr(fhdr, 'NumberOfSections', 0) or 0)
        row['TimeDateStamp'] = int(getattr(fhdr, 'TimeDateStamp', 0) or 0)
        row['Characteristics'] = int(getattr(fhdr, 'Characteristics', 0) or 0)

        row['MajorLinkerVersion'] = int(getattr(oh, 'MajorLinkerVersion', 0) or 0)
        row['MinorLinkerVersion'] = int(getattr(oh, 'MinorLinkerVersion', 0) or 0)
        row['SizeOfCode'] = int(getattr(oh, 'SizeOfCode', 0) or 0)
        row['SizeOfInitializedData'] = int(getattr(oh, 'SizeOfInitializedData', 0) or 0)
        row['AddressOfEntryPoint'] = int(getattr(oh, 'AddressOfEntryPoint', 0) or 0)
        row['ImageBase'] = int(getattr(oh, 'ImageBase', 0) or 0)
        row['SectionAlignment'] = int(getattr(oh, 'SectionAlignment', 0) or 0)
        row['FileAlignment'] = int(getattr(oh, 'FileAlignment', 0) or 0)
        row['MajorOperatingSystemVersion'] = int(getattr(oh, 'MajorOperatingSystemVersion', 0) or 0)
        row['MinorOperatingSystemVersion'] = int(getattr(oh, 'MinorOperatingSystemVersion', 0) or 0)
        row['MajorImageVersion'] = int(getattr(oh, 'MajorImageVersion', 0) or 0)
        row['MinorImageVersion'] = int(getattr(oh, 'MinorImageVersion', 0) or 0)
        row['MajorSubsystemVersion'] = int(getattr(oh, 'MajorSubsystemVersion', 0) or 0)
        row['MinorSubsystemVersion'] = int(getattr(oh, 'MinorSubsystemVersion', 0) or 0)
        row['SizeOfImage'] = int(getattr(oh, 'SizeOfImage', 0) or 0)
        row['SizeOfHeaders'] = int(getattr(oh, 'SizeOfHeaders', 0) or 0)
        row['CheckSum'] = int(getattr(oh, 'CheckSum', 0) or 0)
        row['Subsystem'] = int(getattr(oh, 'Subsystem', 0) or 0)
        row['DllCharacteristics'] = int(getattr(oh, 'DllCharacteristics', 0) or 0)
        row['SizeOfStackReserve'] = int(getattr(oh, 'SizeOfStackReserve', 0) or 0)
        row['SizeOfHeapReserve'] = int(getattr(oh, 'SizeOfHeapReserve', 0) or 0)

        # Imports (Total_DLLs)
        try:
            row['Total_DLLs'] = len(pe.DIRECTORY_ENTRY_IMPORT) if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT') else 0
        except Exception:
            row['Total_DLLs'] = 0

        # Resources
        row['Total_Resources'] = count_resources(pe)

        # Debug entries
        try:
            row['Total_DebugEntries'] = len(pe.DIRECTORY_ENTRY_DEBUG) if hasattr(pe, 'DIRECTORY_ENTRY_DEBUG') else 0
        except Exception:
            row['Total_DebugEntries'] = 0

        # TLS characteristics
        try:
            if hasattr(pe, 'DIRECTORY_ENTRY_TLS') and pe.DIRECTORY_ENTRY_TLS:
                tls = pe.DIRECTORY_ENTRY_TLS.struct
                row['TLS_Characteristics'] = int(getattr(tls, 'Characteristics', 0) or 0)
            else:
                row['TLS_Characteristics'] = 0
        except Exception:
            row['TLS_Characteristics'] = 0

        # Load config
        lc_size, lc_cookie, lc_sehandler = get_load_config_values(pe)
        row['LoadConfig_Size'] = lc_size
        row['LoadConfig_SecurityCookie'] = lc_cookie
        row['LoadConfig_SEHandlerTable'] = lc_sehandler

        # Packed heuristic: high entropy in file or in any section
        try:
            max_sec_entropy = 0.0
            for s in pe.sections:
                sec_data = s.get_data() or b''
                max_sec_entropy = max(max_sec_entropy, entropy(sec_data))
            row['Packed'] = 1 if (row.get('Entropy_Total', 0) > 7.5 or max_sec_entropy > 7.5) else 0
        except Exception:
            row['Packed'] = 0

        pe.close()
    except pefile.PEFormatError:
        # not a valid PE; leave defaults (zeros) except FileSize and maybe compute entropy
        try:
            with open(p, 'rb') as fh:
                data = fh.read()
            row['Entropy_Total'] = entropy(data)
            row['Packed'] = 1 if row['Entropy_Total'] > 7.5 else 0
        except Exception:
            pass
    except Exception as e:
        # any other error, return zeros but include FileSize
        print(f"Warning: error parsing PE {p}: {e}", file=sys.stderr)

    # ensure all keys present and numeric
    for k in list(row.keys()):
        if row[k] is None:
            row[k] = 0
    df = pd.DataFrame([row], columns=model_cols)
    return df


def main():
    if len(sys.argv) != 3:
        print("Usage: python3 pe_to_features.py input.exe out.csv")
        sys.exit(1)
    inp = Path(sys.argv[1])
    out = Path(sys.argv[2])

    if not MODEL_COLS.exists():
        print(f"Missing {MODEL_COLS}. Run the training script first to produce model_columns.json")
        sys.exit(1)

    with open(MODEL_COLS, 'r') as fh:
        model_cols = json.load(fh)

    df = to_features(inp, model_cols)
    df.to_csv(out, index=False)
    print(f"Wrote features to {out}")


if __name__ == '__main__':
    main()
