import os
import joblib
import pandas as pd

from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.ensemble import RandomForestClassifier
from sklearn.calibration import CalibratedClassifierCV

from src.feature_extraction_hybrid import extrair_features_hybrid
from src.training_config import build_training_parser, resolve_training_config
from src.training_metrics import (
    calculate_metrics,
    cv_summary,
    find_best_threshold,
    predict_with_threshold,
    save_metrics,
)


# =========================
# CONFIG
# =========================

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

DEFAULT_USE_SAMPLE = True
DEFAULT_SAMPLE_FILENAME = "urls_raw_10000.csv"
DEFAULT_USE_SLOW_FEATURES = True
DEFAULT_PHISHING_THRESHOLD = 0.50
DEFAULT_MODEL_FILENAME = "phishing_model_full.pkl"
DEFAULT_FEATURES_FILENAME = "feature_names_full.pkl"
DEFAULT_METRICS_FILENAME = "metrics_full.json"


# =========================
# DATASET
# =========================

def carregar_dataset(dataset_path):
    if not os.path.exists(dataset_path):
        raise FileNotFoundError(f"Arquivo não encontrado: {dataset_path}")

    data = pd.read_csv(dataset_path)
    data.columns = data.columns.str.strip()

    data = data.rename(columns={
        "URL": "url",
        "Label": "label"
    })

    if "url" not in data.columns or "label" not in data.columns:
        raise ValueError("O CSV precisa ter as colunas: url,label")

    data = data.dropna(subset=["url", "label"])

    data["label"] = data["label"].replace({
        "good": 1,
        "bad": -1
    })

    data["label"] = pd.to_numeric(data["label"], errors="coerce")
    data = data.dropna(subset=["label"])
    data["label"] = data["label"].astype(int)

    return data


# =========================
# FEATURE EXTRACTION
# =========================

def construir_features(dataframe, use_slow_features):
    registros = []
    labels = []

    total = len(dataframe)

    for i, row in dataframe.iterrows():
        url = str(row["url"]).strip()
        label = int(row["label"])

        try:
            feats = extrair_features_hybrid(url, include_slow=use_slow_features)
            registros.append(feats)
            labels.append(label)
            print(f"[{i+1}/{total}] OK -> {url}")
        except Exception as e:
            print(f"[{i+1}/{total}] ERRO -> {url} | {e}")

    X = pd.DataFrame(registros)
    y = pd.Series(labels, name="label")

    return X, y


# =========================
# CUSTOM PREDICTION
# =========================

def prever_com_threshold(model, X, threshold=0.50):
    proba = model.predict_proba(X)
    classes = list(model.classes_)

    if -1 not in classes or 1 not in classes:
        raise ValueError(f"Classes inesperadas no modelo: {classes}")

    idx_phishing = classes.index(-1)
    prob_phishing = proba[:, idx_phishing]

    pred = [-1 if p >= threshold else 1 for p in prob_phishing]
    return pred, prob_phishing


# =========================
# MAIN
# =========================

def parse_args():
    parser = build_training_parser(
        description="Treina o modelo full de detecção de phishing.",
        default_sample_filename=DEFAULT_SAMPLE_FILENAME,
        default_model_filename=DEFAULT_MODEL_FILENAME,
        default_features_filename=DEFAULT_FEATURES_FILENAME,
        default_metrics_filename=DEFAULT_METRICS_FILENAME,
    )
    return parser.parse_args()


def main():
    args = parse_args()
    config = resolve_training_config(
        args=args,
        base_dir=BASE_DIR,
        default_sample_filename=DEFAULT_SAMPLE_FILENAME,
        default_use_sample=DEFAULT_USE_SAMPLE,
        default_use_slow_features=DEFAULT_USE_SLOW_FEATURES,
        default_threshold=DEFAULT_PHISHING_THRESHOLD,
        default_model_filename=DEFAULT_MODEL_FILENAME,
        default_features_filename=DEFAULT_FEATURES_FILENAME,
        default_metrics_filename=DEFAULT_METRICS_FILENAME,
    )

    print("=" * 60)
    print("CONFIGURAÇÃO DO TREINO FULL")
    print("=" * 60)
    print(f"Dataset: {config['dataset_path']}")
    print(f"Use sample: {config['use_sample']}")
    print(f"Sample filename: {config['sample_filename']}")
    print(f"Modo lento: {config['use_slow_features']}")
    print(f"Threshold phishing: {config['threshold']}")
    print(f"Auto threshold: {config['auto_threshold']}")
    print(f"Métrica de threshold: {config['threshold_metric']}")
    print(f"Modelo: {config['model_path']}")
    print(f"Features: {config['features_path']}")
    print(f"Métricas: {config['metrics_path']}")
    print("=" * 60)

    data = carregar_dataset(config["dataset_path"])
    X, y = construir_features(data, config["use_slow_features"])

    if X.empty:
        raise ValueError("Nenhuma feature foi extraída com sucesso.")

    print("\nQuantidade de amostras válidas:", len(X))
    print("Quantidade de features:", len(X.columns))

    base_model = RandomForestClassifier(
        n_estimators=400,
        max_depth=25,
        min_samples_split=4,
        min_samples_leaf=2,
        class_weight={-1: 3, 1: 1},
        random_state=42,
        n_jobs=4
    )

    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    scores = cross_val_score(base_model, X, y, cv=cv, scoring="accuracy", n_jobs=2)
    cv_metrics = cv_summary(scores)

    print("\nCross-validation scores:")
    print(cv_metrics["scores"])
    print("Média CV:", cv_metrics["mean"])

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.2,
        random_state=42,
        stratify=y
    )

    base_model.fit(X_train, y_train)

    model = CalibratedClassifierCV(base_model, method="sigmoid", cv=5)
    model.fit(X_train, y_train)

    threshold_used = config["threshold"]
    threshold_source = "fixed"

    _, prob_phishing = prever_com_threshold(model, X_test, threshold=threshold_used)

    if config["auto_threshold"]:
        best_threshold = find_best_threshold(
            y_true=y_test,
            prob_phishing=prob_phishing,
            metric_name=config["threshold_metric"],
        )
        threshold_used = best_threshold["threshold"]
        threshold_source = f"auto:{config['threshold_metric']}"
        metrics = best_threshold["metrics"]
        pred = predict_with_threshold(prob_phishing, threshold_used)
    else:
        pred = predict_with_threshold(prob_phishing, threshold_used)
        metrics = calculate_metrics(y_test, pred, prob_phishing)

    print("\nClassification report:")
    print(pd.DataFrame(metrics["classification_report"]).transpose())

    print("\nConfusion matrix:")
    print(metrics["confusion_matrix"])

    print("\nAccuracy:", metrics["accuracy"])
    print("Balanced accuracy:", metrics["balanced_accuracy"])
    print("Precision phishing:", metrics["precision_phishing"])
    print("Recall phishing:", metrics["recall_phishing"])
    print("F1 phishing:", metrics["f1_phishing"])
    print("ROC AUC phishing:", metrics["roc_auc_phishing"])
    print("Threshold usado:", threshold_used)
    print("Origem do threshold:", threshold_source)

    os.makedirs(os.path.join(BASE_DIR, "model"), exist_ok=True)
    joblib.dump(model, config["model_path"])
    joblib.dump(list(X.columns), config["features_path"])

    metrics_payload = {
        "config": {
            "dataset_path": config["dataset_path"],
            "use_sample": config["use_sample"],
            "sample_filename": config["sample_filename"],
            "use_slow_features": config["use_slow_features"],
            "threshold_requested": config["threshold"],
            "threshold_used": threshold_used,
            "threshold_source": threshold_source,
            "threshold_metric": config["threshold_metric"],
            "auto_threshold": config["auto_threshold"],
            "model_path": config["model_path"],
            "features_path": config["features_path"],
        },
        "dataset": {
            "num_samples": int(len(X)),
            "num_features": int(len(X.columns)),
        },
        "cross_validation": cv_metrics,
        "test_metrics": metrics,
    }
    save_metrics(config["metrics_path"], metrics_payload)

    print("\nModelo FULL salvo com sucesso:")
    print(config["model_path"])
    print(config["features_path"])
    print(config["metrics_path"])

    importances = base_model.feature_importances_
    feature_importance = pd.Series(importances, index=X.columns).sort_values(ascending=False)

    print("\nImportância das features FULL:")
    print(feature_importance.head(30))


if __name__ == "__main__":
    main()
