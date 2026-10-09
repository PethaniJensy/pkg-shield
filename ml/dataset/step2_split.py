import pandas as pd
from sklearn.model_selection import train_test_split
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
INPUT_PATH = os.path.join(BASE_DIR, "dataset_clean.csv")

df = pd.read_csv(INPUT_PATH)

# Stratified split to keep 50/50 balance in all sets
train_df, temp_df = train_test_split(df, test_size=0.30, random_state=42, stratify=df['Level'])
val_df, test_df = train_test_split(temp_df, test_size=0.50, random_state=42, stratify=temp_df['Level'])

train_df.to_csv(os.path.join(BASE_DIR, "train.csv"), index=False)
val_df.to_csv(os.path.join(BASE_DIR, "val.csv"), index=False)
test_df.to_csv(os.path.join(BASE_DIR, "test.csv"), index=False)

print(f"[+] Stratified Split Complete (70 / 15 / 15):")
print(f"    • Train set:      {len(train_df)} rows")
print(f"    • Validation set: {len(val_df)} rows")
print(f"    • Test set:       {len(test_df)} rows")
