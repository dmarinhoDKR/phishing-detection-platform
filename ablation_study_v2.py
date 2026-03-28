import argparse
import os

import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split

from train_model_v2 import carregar_dataset, construir_features, prever_com_threshold
from src.training_config import env_or_default, load_dotenv_file
from src.training_metrics import calculate_metrics, find_best_threshold, predict_with_threshold, save_metrics


BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DEFAULT_SAMPLE_FILENAME = "urls_raw_50000.csv"
DEFAULT_THRESHOLD = 0.50
DEFAULT_METRICS_PATH = os.path.join(BASE_DIR, "model", "ablation_v2.json")

NEW_OFFLINE_FEATURES = [
    "digit_ratio",
    "hostname_digit_count",
    "hostname_digit_ratio",
    "special_char_ratio",
    "suspicious_word_count",
    "hostname_entropy",
    "domain_token_count",
    "path_depth",
    "path_token_count",
    "query_param_count",
]

WEAK_FEATURES = [
    "Shortining_Service",
    "double_slash_redirecting",
    "having_At_Symbol",
    "has_encoding",
    "suspicious_tld",
]

TAIL_FEATURES = WEAK_FEATURES + [
    "having_IP_Address",
    "Prefix_Suffix",
]


def parse_bool(value):
    normalized = str(value).strip().lower()
    return normalized in {"1", "true", "yes", "y", "on"}


def parse_args():
    parser = argparse.ArgumentParser(description="Roda uma ablação simples para o modelo v2.")
    parser.add_argument("--dotenv", default=".env", help="Arquivo .env para carregar variáveis de ambiente.")
    parser.add_argument("--dataset", default=None, help="Caminho do CSV de entrada.")
    parser.add_argument("--sample-filename", default=None, help="Nome do sample dentro de data/.")
    parser.add_argument("--use-sample", dest="use_sample", action="store_true", help="Usa um sample dentro de data/.")
    parser.add_argument("--full-dataset", dest="use_sample", action="store_false", help="Usa data/urls_raw.csv.")
    parser.add_argument("--threshold", type=float, default=None, help="Threshold fixo.")
    parser.add_argument("--auto-threshold", dest="auto_threshold", action="store_true", help="Escolhe threshold automaticamente.")
    parser.add_argument("--fixed-threshold", dest="auto_threshold", action="store_false", help="Usa o threshold informado.")
    parser.add_argument(
        "--threshold-metric",
        choices=["f1_phishing", "recall_phishing", "precision_phishing", "balanced_accuracy", "accuracy"],
        default=None,
        help="Métrica usada para auto threshold.",
    )
    parser.add_argument("--metrics-path", default=None, help="Arquivo JSON de saída para os resultados.")
    parser.add_argument(
        "--scenario-set",
        choices=["basic", "extended"],
        default="basic",
        help="Conjunto de cenários da ablação. 'basic' preserva o comportamento atual; 'extended' adiciona subconjuntos do baseline de 23 features.",
    )
    parser.set_defaults(use_sample=None, auto_threshold=None)
    return parser.parse_args()


def resolve_config(args):
    dotenv_path = (args.dotenv or "").strip()
    if dotenv_path:
        if not os.path.isabs(dotenv_path):
            dotenv_path = os.path.join(BASE_DIR, dotenv_path)
        load_dotenv_file(dotenv_path)

    use_sample = args.use_sample
    if use_sample is None:
        use_sample = env_or_default("TRAIN_USE_SAMPLE", True, parse_bool)

    sample_filename = args.sample_filename or env_or_default("TRAIN_SAMPLE_FILENAME", DEFAULT_SAMPLE_FILENAME)
    threshold = args.threshold if args.threshold is not None else env_or_default("TRAIN_PHISHING_THRESHOLD", DEFAULT_THRESHOLD, float)
    auto_threshold = args.auto_threshold
    if auto_threshold is None:
        auto_threshold = env_or_default("TRAIN_AUTO_THRESHOLD", False, parse_bool)
    threshold_metric = args.threshold_metric or env_or_default("TRAIN_THRESHOLD_METRIC", "f1_phishing")

    dataset_path = args.dataset or os.getenv("TRAIN_DATASET_PATH")
    if dataset_path:
        if not os.path.isabs(dataset_path):
            dataset_path = os.path.join(BASE_DIR, dataset_path)
    elif use_sample:
        dataset_path = os.path.join(BASE_DIR, "data", sample_filename)
    else:
        dataset_path = os.path.join(BASE_DIR, "data", "urls_raw.csv")

    metrics_path = args.metrics_path or os.getenv("ABLATION_METRICS_PATH") or DEFAULT_METRICS_PATH
    if not os.path.isabs(metrics_path):
        metrics_path = os.path.join(BASE_DIR, metrics_path)

    return {
        "dataset_path": dataset_path,
        "use_sample": use_sample,
        "sample_filename": sample_filename,
        "threshold": threshold,
        "auto_threshold": auto_threshold,
        "threshold_metric": threshold_metric,
        "metrics_path": metrics_path,
    }


def build_model():
    return RandomForestClassifier(
        n_estimators=400,
        max_depth=25,
        min_samples_split=4,
        min_samples_leaf=2,
        class_weight={-1: 3, 1: 1},
        random_state=42,
        n_jobs=4,
    )


def evaluate_scenario(name, X_train, X_test, y_train, y_test, feature_columns, config):
    base_model = build_model()
    base_model.fit(X_train[feature_columns], y_train)

    model = CalibratedClassifierCV(base_model, method="sigmoid", cv=5)
    model.fit(X_train[feature_columns], y_train)

    _, prob_phishing = prever_com_threshold(model, X_test[feature_columns], threshold=config["threshold"])

    threshold_used = config["threshold"]
    threshold_source = "fixed"

    if config["auto_threshold"]:
        best = find_best_threshold(y_test, prob_phishing, config["threshold_metric"])
        threshold_used = best["threshold"]
        threshold_source = f"auto:{config['threshold_metric']}"
        metrics = best["metrics"]
    else:
        y_pred = predict_with_threshold(prob_phishing, threshold_used)
        metrics = calculate_metrics(y_test, y_pred, prob_phishing)

    return {
        "feature_count": len(feature_columns),
        "threshold_used": threshold_used,
        "threshold_source": threshold_source,
        "metrics": metrics,
        "top_features": pd.Series(base_model.feature_importances_, index=feature_columns)
        .sort_values(ascending=False)
        .head(15)
        .to_dict(),
    }


def build_scenarios(all_columns, scenario_set):
    scenarios = {
        "legacy_core": [col for col in all_columns if col not in NEW_OFFLINE_FEATURES],
        "production_default": list(all_columns),
    }

    if scenario_set == "extended":
        top15 = list(all_columns[:15])
        top10 = list(all_columns[:10])
        scenarios.update(
            {
                "production_minus_weak": [col for col in all_columns if col not in WEAK_FEATURES],
                "production_minus_tail": [col for col in all_columns if col not in TAIL_FEATURES],
                "production_top15": top15,
                "production_top10": top10,
            }
        )

    deduplicated = {}
    seen = set()
    for name, columns in scenarios.items():
        normalized = tuple(columns)
        if not columns or normalized in seen:
            continue
        seen.add(normalized)
        deduplicated[name] = columns

    return deduplicated


def main():
    args = parse_args()
    config = resolve_config(args)

    print("=" * 60)
    print("ABLACAO V2")
    print("=" * 60)
    print(f"Dataset: {config['dataset_path']}")
    print(f"Use sample: {config['use_sample']}")
    print(f"Threshold base: {config['threshold']}")
    print(f"Auto threshold: {config['auto_threshold']}")
    print(f"Métrica de threshold: {config['threshold_metric']}")
    print(f"Cenários: {args.scenario_set}")
    print("=" * 60)

    data = carregar_dataset(config["dataset_path"])
    X, y = construir_features(data, use_slow_features=False)

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.2,
        random_state=42,
        stratify=y,
    )

    ordered_columns = list(
        pd.Series(build_model().fit(X_train, y_train).feature_importances_, index=X.columns)
        .sort_values(ascending=False)
        .index
    )
    scenarios = build_scenarios(ordered_columns, args.scenario_set)

    results = {}
    summary_rows = []

    for name, feature_columns in scenarios.items():
        print(f"\nRodando cenário: {name} ({len(feature_columns)} features)")
        result = evaluate_scenario(name, X_train, X_test, y_train, y_test, feature_columns, config)
        results[name] = result

        metrics = result["metrics"]
        summary_rows.append(
            {
                "scenario": name,
                "feature_count": result["feature_count"],
                "threshold_used": result["threshold_used"],
                "accuracy": metrics["accuracy"],
                "balanced_accuracy": metrics["balanced_accuracy"],
                "precision_phishing": metrics["precision_phishing"],
                "recall_phishing": metrics["recall_phishing"],
                "f1_phishing": metrics["f1_phishing"],
                "roc_auc_phishing": metrics["roc_auc_phishing"],
            }
        )

    summary_df = pd.DataFrame(summary_rows).sort_values(by="f1_phishing", ascending=False)
    print("\nResumo da ablação:")
    print(summary_df.to_string(index=False))

    payload = {
        "config": config,
        "dataset": {
            "num_samples": int(len(X)),
            "num_features_total": int(len(X.columns)),
        },
        "summary": summary_rows,
        "results": results,
    }
    save_metrics(config["metrics_path"], payload)
    print(f"\nResultados salvos em: {config['metrics_path']}")


if __name__ == "__main__":
    main()
