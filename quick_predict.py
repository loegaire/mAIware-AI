#!/usr/bin/env python3
"""
Fast prediction script - optimized for mAIware integration.
Handles large files efficiently and has shorter timeout.
"""
import sys
import json
from pathlib import Path

def quick_predict(file_path):
    """Fast prediction without full feature extraction."""
    result = {
        "success": True,
        "classification": "Benign",
        "confidence": 0.5,
        "is_pe": False,  # Default to False until confirmed
        "entropy": {},
        "api_imports": [],
        "suspicious_strings": [],
        "cfg_image": None,
        "note": "Fast heuristic analysis"
    }
    
    # Try quick PE check
    try:
        with open(file_path, 'rb') as f:
            header = f.read(2)
            if header == b'MZ':
                result["is_pe"] = True
                result["confidence"] = 0.85
                # Read more for quick entropy check
                f.seek(0)
                data = f.read(min(1024 * 1024, Path(file_path).stat().st_size))  # Read up to 1MB
                
                # Quick entropy calc
                from collections import Counter
                import math
                if data:
                    counts = Counter(data)
                    probs = [c / len(data) for c in counts.values()]
                    ent = -sum(p * math.log2(p) for p in probs if p > 0)
                    result["entropy"]["header"] = round(ent, 2)
                    
                    if ent > 7.5:
                        result["classification"] = "Suspicious"
                        result["confidence"] = 0.75
                        result["note"] = "High entropy detected (possible packing/encryption)"
            else:
                result["is_pe"] = False
                result["classification"] = "Benign"
                result["confidence"] = 0.9
                result["note"] = "Not a Windows PE executable"
    except Exception as e:
        result["success"] = False
        result["error"] = str(e)
        result["is_pe"] = False
    
    return result

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(json.dumps({"success": False, "error": "No file specified"}))
        sys.exit(1)
    
    file_path = sys.argv[1]
    result = quick_predict(file_path)
    print(json.dumps(result, indent=2))
