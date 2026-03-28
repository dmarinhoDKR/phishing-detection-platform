import argparse
import os


def _strip_quotes(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


def load_dotenv_file(dotenv_path: str) -> None:
    if not dotenv_path or not os.path.exists(dotenv_path):
        return

    with open(dotenv_path, "r", encoding="utf-8") as file:
        for raw_line in file:
            line = raw_line.strip()

            if not line or line.startswith("#") or "=" not in line:
                continue

            key, value = line.split("=", 1)
            key = key.strip()
            value = _strip_quotes(value)

            if key and key not in os.environ:
                os.environ[key] = value


def parse_bool(value):
    if isinstance(value, bool):
        return value

    normalized = str(value).strip().lower()
    if normalized in {"1", "true", "yes", "y", "on"}:
        return True
    if normalized in {"0", "false", "no", "n", "off"}:
        return False

    raise argparse.ArgumentTypeError(f"Valor booleano inválido: {value}")


def env_or_default(name: str, default, caster=str):
    value = os.getenv(name)
    if value is None or value == "":
        return default
    return caster(value)


def build_training_parser(
    description: str,
    default_sample_filename: str,
    default_model_filename: str,
    default_features_filename: str,
    default_metrics_filename: str,
):
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument(
        "--dotenv",
        default=".env",
        help="Arquivo .env para carregar variáveis de ambiente. Use vazio para ignorar.",
    )
    parser.add_argument(
        "--dataset",
        help="Caminho do CSV de entrada. Se informado, tem prioridade sobre --sample-filename e --use-sample.",
    )
    parser.add_argument(
        "--sample-filename",
        default=None,
        help=f"Nome do sample dentro de data/. Padrão: {default_sample_filename}",
    )
    parser.add_argument(
        "--use-sample",
        dest="use_sample",
        action="store_true",
        help="Usa um sample dentro de data/ como dataset de treino.",
    )
    parser.add_argument(
        "--full-dataset",
        dest="use_sample",
        action="store_false",
        help="Usa data/urls_raw.csv como dataset de treino.",
    )
    parser.add_argument(
        "--slow-features",
        dest="use_slow_features",
        action="store_true",
        help="Habilita features lentas durante a extração.",
    )
    parser.add_argument(
        "--fast-features",
        dest="use_slow_features",
        action="store_false",
        help="Desabilita features lentas durante a extração.",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=None,
        help="Threshold usado para classificar phishing a partir da probabilidade.",
    )
    parser.add_argument(
        "--model-path",
        default=None,
        help=f"Caminho do arquivo do modelo. Padrão: model/{default_model_filename}",
    )
    parser.add_argument(
        "--features-path",
        default=None,
        help=f"Caminho do arquivo com nomes das features. Padrão: model/{default_features_filename}",
    )
    parser.add_argument(
        "--metrics-path",
        default=None,
        help=f"Caminho do arquivo de métricas. Padrão: model/{default_metrics_filename}",
    )
    parser.add_argument(
        "--auto-threshold",
        dest="auto_threshold",
        action="store_true",
        help="Escolhe automaticamente o threshold no conjunto de teste com base na métrica definida.",
    )
    parser.add_argument(
        "--fixed-threshold",
        dest="auto_threshold",
        action="store_false",
        help="Usa exatamente o threshold informado em vez de selecionar automaticamente.",
    )
    parser.add_argument(
        "--threshold-metric",
        choices=["f1_phishing", "recall_phishing", "precision_phishing", "balanced_accuracy", "accuracy"],
        default=None,
        help="Métrica usada para escolher o melhor threshold quando --auto-threshold estiver ativo.",
    )

    parser.set_defaults(use_sample=None, use_slow_features=None, auto_threshold=None)
    return parser


def resolve_training_config(
    args,
    base_dir: str,
    default_sample_filename: str,
    default_use_sample: bool,
    default_use_slow_features: bool,
    default_threshold: float,
    default_model_filename: str,
    default_features_filename: str,
    default_metrics_filename: str,
):
    dotenv_path = (args.dotenv or "").strip()
    if dotenv_path:
        if not os.path.isabs(dotenv_path):
            dotenv_path = os.path.join(base_dir, dotenv_path)
        load_dotenv_file(dotenv_path)

    use_sample = (
        args.use_sample
        if args.use_sample is not None
        else env_or_default("TRAIN_USE_SAMPLE", default_use_sample, parse_bool)
    )
    sample_filename = args.sample_filename or env_or_default(
        "TRAIN_SAMPLE_FILENAME",
        default_sample_filename,
    )
    use_slow_features = (
        args.use_slow_features
        if args.use_slow_features is not None
        else env_or_default("TRAIN_USE_SLOW_FEATURES", default_use_slow_features, parse_bool)
    )
    threshold = args.threshold if args.threshold is not None else env_or_default(
        "TRAIN_PHISHING_THRESHOLD",
        default_threshold,
        float,
    )
    auto_threshold = (
        args.auto_threshold
        if args.auto_threshold is not None
        else env_or_default("TRAIN_AUTO_THRESHOLD", False, parse_bool)
    )
    threshold_metric = args.threshold_metric or env_or_default(
        "TRAIN_THRESHOLD_METRIC",
        "f1_phishing",
    )

    dataset_path = args.dataset or os.getenv("TRAIN_DATASET_PATH")
    if dataset_path:
        if not os.path.isabs(dataset_path):
            dataset_path = os.path.join(base_dir, dataset_path)
    elif use_sample:
        dataset_path = os.path.join(base_dir, "data", sample_filename)
    else:
        dataset_path = os.path.join(base_dir, "data", "urls_raw.csv")

    model_path = args.model_path or os.getenv("TRAIN_MODEL_PATH")
    if model_path:
        if not os.path.isabs(model_path):
            model_path = os.path.join(base_dir, model_path)
    else:
        model_path = os.path.join(base_dir, "model", default_model_filename)

    features_path = args.features_path or os.getenv("TRAIN_FEATURES_PATH")
    if features_path:
        if not os.path.isabs(features_path):
            features_path = os.path.join(base_dir, features_path)
    else:
        features_path = os.path.join(base_dir, "model", default_features_filename)

    metrics_path = args.metrics_path or os.getenv("TRAIN_METRICS_PATH")
    if metrics_path:
        if not os.path.isabs(metrics_path):
            metrics_path = os.path.join(base_dir, metrics_path)
    else:
        metrics_path = os.path.join(base_dir, "model", default_metrics_filename)

    return {
        "dataset_path": dataset_path,
        "use_sample": use_sample,
        "sample_filename": sample_filename,
        "use_slow_features": use_slow_features,
        "threshold": threshold,
        "auto_threshold": auto_threshold,
        "threshold_metric": threshold_metric,
        "model_path": model_path,
        "features_path": features_path,
        "metrics_path": metrics_path,
    }
