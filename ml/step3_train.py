import pandas as pd
import numpy as np
import json
import joblib
import os
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATASET_DIR = os.path.join(BASE_DIR, "dataset")
MODELS_DIR = os.path.join(BASE_DIR, "models")
os.makedirs(MODELS_DIR, exist_ok=True)

print("=" * 70)
print("  🛡️  PKG-SHIELD: RANDOM FOREST MODEL TRAINING PIPELINE")
print("=" * 70)

# 1. Load train and test splits
print("\n[*] Loading dataset splits...")
train_df = pd.read_csv(os.path.join(DATASET_DIR, "train.csv"))
test_df = pd.read_csv(os.path.join(DATASET_DIR, "test.csv"))

print(f"[+] Train samples: {len(train_df)}")
print(f"[+] Test samples:  {len(test_df)}")

# 2. Strict metadata removal (Prevent Data Leakage)
METADATA_COLS = [
    'Package_ID', 'Package_Name', 'Package_Version',
    'Static_Version', 'Dynamic_Version', 'Match_Method', 'Level'
]

# Identify the 112 features
feature_cols = [c for c in train_df.columns if c not in METADATA_COLS and (c.startswith('feature_') or c.startswith('dynamic_'))]

print(f"\n[+] Extracting pure feature matrix: {len(feature_cols)} features (37 Static + 75 Dynamic)")

X_train = train_df[feature_cols].values
y_train = train_df['Level'].values

X_test = test_df[feature_cols].values
y_test = test_df['Level'].values

# 3. Train Random Forest Model
print("\n[*] Training Random Forest Classifier (200 trees, balanced weights)...")
rf = RandomForestClassifier(
    n_estimators=200,
    max_depth=16,
    min_samples_split=5,
    min_samples_leaf=2,
    class_weight="balanced",
    random_state=42,
    n_jobs=-1
)
rf.fit(X_train, y_train)
print("[+] Model training completed!")

# 4. Evaluate on Unseen Test Set
print("\n[*] Evaluating model on test set...")
y_pred = rf.predict(X_test)
y_prob = rf.predict_proba(X_test)[:, 1]

acc = accuracy_score(y_test, y_pred)
prec = precision_score(y_test, y_pred)
rec = recall_score(y_test, y_pred)
f1 = f1_score(y_test, y_pred)
auc = roc_auc_score(y_test, y_prob)
cm = confusion_matrix(y_test, y_pred)

print("\n" + "=" * 45)
print("       MODEL EVALUATION RESULTS")
print("=" * 45)
print(f"  Accuracy  : {acc * 100:.2f}%")
print(f"  Precision : {prec * 100:.2f}%")
print(f"  Recall    : {rec * 100:.2f}%")
print(f"  F1-Score  : {f1 * 100:.2f}%")
print(f"  ROC-AUC   : {auc * 100:.2f}%")
print("=" * 45)
print("\nConfusion Matrix:")
print(f"  [[TN: {cm[0][0]}, FP: {cm[0][1]}],")
print(f"   [FN: {cm[1][0]}, TP: {cm[1][1]}]]")

# 5. Save model and evaluation artifacts
MODEL_OUT = os.path.join(MODELS_DIR, "safepip_rf_model.pkl")
joblib.dump(rf, MODEL_OUT)
print(f"\n[+] Trained model saved to: {MODEL_OUT}")

# Save metrics
metrics = {
    "accuracy": acc,
    "precision": prec,
    "recall": rec,
    "f1_score": f1,
    "roc_auc": auc,
    "confusion_matrix": cm.tolist()
}
with open(os.path.join(MODELS_DIR, "metrics.json"), "w") as f:
    json.dump(metrics, f, indent=2)

# Save feature importance
importance_df = pd.DataFrame({
    "feature": feature_cols,
    "importance": rf.feature_importances_
}).sort_values(by="importance", ascending=False)

importance_df.to_csv(os.path.join(MODELS_DIR, "feature_importance.csv"), index=False)
print(f"[+] Feature importances saved to: {os.path.join(MODELS_DIR, 'feature_importance.csv')}")

print("\n[+] Top 5 Most Predictive Security Features:")
for idx, row in importance_df.head(5).iterrows():
    print(f"    • {row['feature']}: {row['importance']:.4f}")

print("\n🎉 Training pipeline 100% complete!")
