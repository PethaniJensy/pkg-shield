import pandas as pd
import os

# Use dynamic directory of this script so it works from anywhere
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
INPUT_PATH = os.path.join(BASE_DIR, "hybrid_dataset.xlsx")
OUTPUT_PATH = os.path.join(BASE_DIR, "dataset_clean.csv")

print("[*] Loading hybrid dataset from Excel...")
df = pd.read_excel(INPUT_PATH)
print(f"[+] Loaded raw dataset: {df.shape[0]} rows, {df.shape[1]} columns")

# Label Distribution
print("\n[*] Label Breakdown:")
print(df['Level'].value_counts())

# Separate metadata from ML feature columns
static_cols = [c for c in df.columns if c.startswith('feature_')]
dynamic_cols = [c for c in df.columns if c.startswith('dynamic_')]
feature_cols = static_cols + dynamic_cols

print(f"\n[+] Verified Features: {len(static_cols)} Static + {len(dynamic_cols)} Dynamic = {len(feature_cols)} Total Features")

# Check for missing values in features
null_counts = df[feature_cols].isnull().sum().sum()
if null_counts > 0:
    print(f"[!] Warning: Found {null_counts} null values in features! Imputing with 0...")
    df[feature_cols] = df[feature_cols].fillna(0)
else:
    print("[+] Perfect: Zero missing values across all 112 feature columns!")

# Save clean CSV
df.to_csv(OUTPUT_PATH, index=False)
print(f"[+] Clean dataset successfully saved to: {OUTPUT_PATH}")
