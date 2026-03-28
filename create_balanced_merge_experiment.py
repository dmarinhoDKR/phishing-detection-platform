import argparse
import json
import os

import pandas as pd


BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DEFAULT_REPORT_PATH = os.path.join(BASE_DIR, "model", "external_dataset_merge_report.json")
DEFAULT_OUTPUT_PATH = os.path.join(BASE_DIR, "data", "experiments", "urls_raw_balanced_experiment.csv")
DEFAULT_SUMMARY_PATH = os.path.join(BASE_DIR, "model", "experiments", "balanced_merge_experiment_report.json")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Cria um dataset experimental balanceado combinando o dataset antigo com parte controlada do dataset novo."
    )
    parser.add_argument(
        "--merge-report",
        default=DEFAULT_REPORT_PATH,
        help="Relatório JSON gerado no merge do dataset externo.",
    )
    parser.add_argument(
        "--output-path",
        default=DEFAULT_OUTPUT_PATH,
        help="CSV de saída do experimento balanceado.",
    )
    parser.add_argument(
        "--strategy",
        choices=["match_phishing", "double_phishing", "custom"],
        default="match_phishing",
        help="Estratégia de amostragem do dataset novo.",
    )
    parser.add_argument(
        "--new-legit-count",
        type=int,
        default=None,
        help="Quantidade de URLs legítimas novas para a estratégia custom.",
    )
    parser.add_argument(
        "--new-phishing-count",
        type=int,
        default=None,
        help="Quantidade de URLs phishing novas para a estratégia custom.",
    )
    parser.add_argument(
        "--random-state",
        type=int,
        default=42,
        help="Seed da amostragem.",
    )
    return parser.parse_args()


def load_merge_report(report_path: str):
    with open(report_path, "r", encoding="utf-8-sig") as handle:
        return json.load(handle)


def load_dataset(csv_path: str):
    df = pd.read_csv(csv_path)
    df.columns = df.columns.str.strip()
    df = df.rename(columns={"URL": "url", "Label": "label"})
    if "url" not in df.columns or "label" not in df.columns:
        raise ValueError(f"O arquivo {csv_path} precisa ter as colunas url,label")
    df = df.dropna(subset=["url", "label"]).copy()
    df["label"] = df["label"].replace({"good": 1, "bad": -1})
    df["label"] = pd.to_numeric(df["label"], errors="coerce")
    df = df.dropna(subset=["label"]).copy()
    df["label"] = df["label"].astype(int)
    return df[["url", "label"]]


def choose_counts(strategy: str, new_df: pd.DataFrame, custom_legit, custom_phishing):
    phishing_available = int((new_df["label"] == -1).sum())
    legit_available = int((new_df["label"] == 1).sum())

    if strategy == "match_phishing":
        target = min(phishing_available, legit_available)
        return target, target

    if strategy == "double_phishing":
        phishing_target = phishing_available
        legit_target = min(legit_available, phishing_target * 2)
        return legit_target, phishing_target

    if custom_legit is None or custom_phishing is None:
        raise ValueError("Na estratégia custom, informe --new-legit-count e --new-phishing-count.")
    if custom_legit > legit_available or custom_phishing > phishing_available:
        raise ValueError("A contagem custom excede a quantidade disponível no dataset novo.")
    return custom_legit, custom_phishing


def main():
    args = parse_args()
    report_path = args.merge_report
    if not os.path.isabs(report_path):
        report_path = os.path.join(BASE_DIR, report_path)

    output_path = args.output_path
    if not os.path.isabs(output_path):
        output_path = os.path.join(BASE_DIR, output_path)

    if not os.path.exists(report_path):
        raise FileNotFoundError(f"Relatório de merge não encontrado: {report_path}")

    report = load_merge_report(report_path)
    backup_path = report.get("backup_csv")
    source_csv = report.get("source_csv")

    if not backup_path or not os.path.exists(backup_path):
        raise FileNotFoundError("Backup do dataset antigo não encontrado no relatório de merge.")
    if not source_csv or not os.path.exists(source_csv):
        raise FileNotFoundError("Dataset externo original não encontrado no relatório de merge.")

    old_df = load_dataset(backup_path)
    new_raw_df = pd.read_csv(source_csv)
    new_raw_df.columns = new_raw_df.columns.str.strip()
    if "url" not in new_raw_df.columns or "label" not in new_raw_df.columns:
        raise ValueError("O dataset novo precisa ter colunas url,label.")

    new_df = new_raw_df[["url", "label"]].dropna(subset=["url", "label"]).copy()
    new_df["label"] = pd.to_numeric(new_df["label"], errors="coerce")
    new_df = new_df.dropna(subset=["label"]).copy()
    new_df["label"] = new_df["label"].astype(int).map({1: -1, 0: 1})
    new_df = new_df.drop_duplicates(subset=["url"]).copy()

    old_urls = set(old_df["url"])
    new_df = new_df[~new_df["url"].isin(old_urls)].copy()

    legit_count, phishing_count = choose_counts(
        args.strategy,
        new_df,
        args.new_legit_count,
        args.new_phishing_count,
    )

    sampled_legit = new_df[new_df["label"] == 1].sample(n=legit_count, random_state=args.random_state)
    sampled_phishing = new_df[new_df["label"] == -1].sample(n=phishing_count, random_state=args.random_state)

    experiment_df = pd.concat([old_df, sampled_legit, sampled_phishing], ignore_index=True)
    experiment_df = experiment_df.drop_duplicates(subset=["url"], keep="first")

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    experiment_df.to_csv(output_path, index=False, encoding="utf-8")

    summary = {
        "strategy": args.strategy,
        "backup_dataset": backup_path,
        "source_dataset": source_csv,
        "output_path": output_path,
        "old_rows": int(len(old_df)),
        "new_unique_candidates": int(len(new_df)),
        "added_new_legit": int(legit_count),
        "added_new_phishing": int(phishing_count),
        "final_rows": int(len(experiment_df)),
        "final_distribution": {
            str(label): int(count) for label, count in experiment_df["label"].value_counts().sort_index().items()
        },
    }

    summary_path = DEFAULT_SUMMARY_PATH
    os.makedirs(os.path.dirname(summary_path), exist_ok=True)
    with open(summary_path, "w", encoding="utf-8") as handle:
        json.dump(summary, handle, ensure_ascii=False, indent=2)

    print("Dataset experimental criado com sucesso.")
    print(f"Saída: {output_path}")
    print(f"Relatório: {summary_path}")
    print(f"Linhas finais: {len(experiment_df)}")
    print("Distribuição final:")
    print(experiment_df["label"].value_counts().sort_index())


if __name__ == "__main__":
    main()
