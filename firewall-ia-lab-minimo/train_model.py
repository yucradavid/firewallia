import os
import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    classification_report,
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
)

from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.linear_model import LogisticRegression

FEATURES = [
    "total_pkts",
    "tcp_pkts",
    "udp_pkts",
    "other_pkts",
    "unique_dports_count",
    "syn_ratio",
    "avg_pkt_size",
    "duration_sec",
    "bytes_per_sec",
    "port_scan_score",
    "small_syn_score",
    "potential_flood",
    "potential_scan",
]

os.makedirs("models", exist_ok=True)

df = pd.read_csv("data/dataset.csv")

print("Dataset cargado:", df.shape)
print(df["label"].value_counts())

X = df[FEATURES].values
y = df["label"].values

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.30,
    random_state=42,
    stratify=y,
)

scaler = StandardScaler()
X_train_sc = scaler.fit_transform(X_train)
X_test_sc = scaler.transform(X_test)

models = {
    "Random Forest": RandomForestClassifier(
        n_estimators=150,
        max_depth=12,
        class_weight="balanced",
        random_state=42,
    ),
    "Gradient Boosting": GradientBoostingClassifier(random_state=42),
    "Decision Tree": DecisionTreeClassifier(
        max_depth=10,
        class_weight="balanced",
        random_state=42,
    ),
    "Logistic Regression": LogisticRegression(
        max_iter=1000,
        class_weight="balanced",
        random_state=42,
    ),
}

results = []

for name, model in models.items():
    model.fit(X_train_sc, y_train)
    y_pred = model.predict(X_test_sc)

    if hasattr(model, "predict_proba") and "attack" in model.classes_:
        y_score = model.predict_proba(X_test_sc)[:, list(model.classes_).index("attack")]
        y_true_bin = [1 if v == "attack" else 0 for v in y_test]
        auc = roc_auc_score(y_true_bin, y_score)
    else:
        auc = 0

    results.append({
        "model": name,
        "accuracy": accuracy_score(y_test, y_pred),
        "precision_attack": precision_score(y_test, y_pred, pos_label="attack", zero_division=0),
        "recall_attack": recall_score(y_test, y_pred, pos_label="attack", zero_division=0),
        "f1_attack": f1_score(y_test, y_pred, pos_label="attack", zero_division=0),
        "roc_auc": auc,
    })

    print("\n" + "=" * 70)
    print(name)
    print("=" * 70)
    print(classification_report(y_test, y_pred, zero_division=0))
    print("Matriz de confusión:")
    print(confusion_matrix(y_test, y_pred, labels=["normal", "attack"]))

results_df = pd.DataFrame(results)
results_df.to_csv("models/metrics_comparison.csv", index=False)

best_model = models["Random Forest"]

joblib.dump(best_model, "models/firewall_ai_model.joblib")
joblib.dump(scaler, "models/scaler.joblib")

importance = pd.DataFrame({
    "feature": FEATURES,
    "importance": best_model.feature_importances_,
}).sort_values("importance", ascending=False)

importance.to_csv("models/feature_importance.csv", index=False)

print("\nResumen comparativo:")
print(results_df)

print("\n[OK] Modelo guardado en models/firewall_ai_model.joblib")
print("[OK] Scaler guardado en models/scaler.joblib")
print("[OK] Métricas guardadas en models/metrics_comparison.csv")
print("[OK] Importancia de features guardada en models/feature_importance.csv")
