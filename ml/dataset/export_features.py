import pandas as pd
import json
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CSV_PATH = os.path.join(BASE_DIR, "dataset_clean.csv")
MODELS_DIR = os.path.abspath(os.path.join(BASE_DIR, "..", "models"))
os.makedirs(MODELS_DIR, exist_ok=True)

df = pd.read_csv(CSV_PATH)

static_cols = [c for c in df.columns if c.startswith('feature_')]
dynamic_cols = [c for c in df.columns if c.startswith('dynamic_')]
feature_cols = static_cols + dynamic_cols

manifest = {
    "total_features": len(feature_cols),
    "static_feature_count": len(static_cols),
    "dynamic_feature_count": len(dynamic_cols),
    "static_features": static_cols,
    "dynamic_features": dynamic_cols,
    "all_features_ordered": feature_cols
}

OUT_PATH = os.path.join(MODELS_DIR, "feature_list.json")
with open(OUT_PATH, "w") as f:
    json.dump(manifest, f, indent=2)

print(f"[+] Feature contract ({len(feature_cols)} features) saved to: {OUT_PATH}")
