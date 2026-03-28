import os

import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from train_model_v2 import carregar_dataset, construir_features, prever_com_threshold
from src.training_config import build_training_parser, resolve_training_config
from src.training_metrics import (
    calculate_metrics,
    cv_summary,
    find_best_threshold,
    predict_with_threshold,
    save_metrics,
)


BASE_DIR = os.path.abspath(os.path.dirname(__file__))

DEFAULT_USE_SAMPLE = False
DEFAULT_SAMPLE_FILENAME = "urls_raw_50000.csv"
DEFAULT_USE_SLOW_FEATURES = False
DEFAULT_PHISHING_THRESHOLD = 0.50
DEFAULT_METRICS_FILENAME = "benchmark_models_v2.json"


def parse_args():
    parser = build_training_parser(
        description="Compara RandomForest e LogisticRegression com o mesmo dataset e thresholding.",
        default_sample_filename=DEFAULT_SAMPLE_FILENAME,
        default_model_filename="phishing_model_v2.pkl",
        default_features_filename="feature_names_v2.pkl",
        default_metrics_filename=DEFAULT_METRICS_FILENAME,
    )
    return parser.parse_args()


def build_estimators():
    return {
        "random_forest": RandomForestClassifier(
            n_estimators=400,
            max_depth=25,
            min_samples_split=4,
            min_samples_leaf=2,
            class_weight={-1: 3, 1: 1},
            random_state=42,
            n_jobs=4,
        ),
        "logistic_regression": Pipeline(
            steps=[
                ("scaler", StandardScaler()),
                (
                    "model",
                    LogisticRegression(
                        class_weight={-1: 3, 1: 1},
                        max_iter=2000,
                        solver="lbfgs",
                        random_state=42,
                    ),
                ),
            ]
        ),
    }


def evaluate_estimator(name, estimator, X, y, config):
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    scores = cross_val_score(estimator, X, y, cv=cv, scoring="accuracy", n_jobs=2)
    cv_metrics = cv_summary(scores)

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.2,
        random_state=42,
        stratify=y,
    )

    base_estimator = estimator
    base_estimator.fit(X_train, y_train)

    calibrated = CalibratedClassifierCV(base_estimator, method="sigmoid", cv=5)
    calibrated.fit(X_train, y_train)

    threshold_used = config["threshold"]
    threshold_source = "fixed"
    _, prob_phishing = prever_com_threshold(calibrated, X_test, threshold=threshold_used)

    if config["auto_threshold"]:
        best_threshold = find_best_threshold(
            y_true=y_test,
            prob_phishing=prob_phishing,
            metric_name=config["threshold_metric"],
        )
        threshold_used = best_threshold["threshold"]
        threshold_source = f"auto:{config['threshold_metric']}"
        metrics = best_threshold["metrics"]
    else:
        pred = predict_with_threshold(prob_phishing, threshold_used)
        metrics = calculate_metrics(y_test, pred, prob_phishing)

    return {
        "name": name,
        "cross_validation": cv_metrics,
        "threshold_used": threshold_used,
        "threshold_source": threshold_source,
        "metrics": metrics,
    }


def main():
    args = parse_args()
    config = resolve_training_config(
        args=args,
        base_dir=BASE_DIR,
        default_sample_filename=DEFAULT_SAMPLE_FILENAME,
        default_use_sample=DEFAULT_USE_SAMPLE,
        default_use_slow_features=DEFAULT_USE_SLOW_FEATURES,
        default_threshold=DEFAULT_PHISHING_THRESHOLD,
        default_model_filename="phishing_model_v2.pkl",
        default_features_filename="feature_names_v2.pkl",
        default_metrics_filename=DEFAULT_METRICS_FILENAME,
    )

    print("=" * 60)
    print("BENCHMARK DE MODELOS")
    print("=" * 60)
    print(f"Dataset: {config['dataset_path']}")
    print(f"Use sample: {config['use_sample']}")
    print(f"Modo lento: {config['use_slow_features']}")
    print(f"Threshold phishing: {config['threshold']}")
    print(f"Auto threshold: {config['auto_threshold']}")
    print(f"Métrica de threshold: {config['threshold_metric']}")
    print("=" * 60)

    data = carregar_dataset(config["dataset_path"])
    X, y = construir_features(data, config["use_slow_features"])

    results = {}
    summary_rows = []

    for model_name, estimator in build_estimators().items():
        print(f"\nRodando benchmark: {model_name}")
        result = evaluate_estimator(model_name, estimator, X, y, config)
        results[model_name] = result
        metrics = result["metrics"]
        summary_rows.append(
            {
                "model": model_name,
                "threshold_used": result["threshold_used"],
                "accuracy": metrics["accuracy"],
                "balanced_accuracy": metrics["balanced_accuracy"],
                "precision_phishing": metrics["precision_phishing"],
                "recall_phishing": metrics["recall_phishing"],
                "f1_phishing": metrics["f1_phishing"],
                "roc_auc_phishing": metrics["roc_auc_phishing"],
                "cv_accuracy_mean": result["cross_validation"]["mean"],
            }
        )

    summary_df = pd.DataFrame(summary_rows).sort_values(by="f1_phishing", ascending=False)
    print("\nResumo do benchmark:")
    print(summary_df.to_string(index=False))

    payload = {
        "config": {
            "dataset_path": config["dataset_path"],
            "use_sample": config["use_sample"],
            "sample_filename": config["sample_filename"],
            "use_slow_features": config["use_slow_features"],
            "threshold_requested": config["threshold"],
            "threshold_metric": config["threshold_metric"],
            "auto_threshold": config["auto_threshold"],
        },
        "dataset": {
            "num_samples": int(len(X)),
            "num_features": int(len(X.columns)),
        },
        "summary": summary_rows,
        "results": results,
    }
    save_metrics(config["metrics_path"], payload)
    print(f"\nResultados salvos em: {config['metrics_path']}")


if __name__ == "__main__":
    main()
