import argparse
import os
import pandas as pd
from sklearn.model_selection import train_test_split

from src.training_config import env_or_default, load_dotenv_file

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DEFAULT_INPUT_FILENAME = "urls_raw.csv"
DEFAULT_SAMPLE_SIZE = 20000


def parse_args():
    parser = argparse.ArgumentParser(
        description="Cria um sample estratificado do dataset de URLs."
    )
    parser.add_argument(
        "sample_size",
        nargs="?",
        type=int,
        help=f"Tamanho do sample. Padrão: {DEFAULT_SAMPLE_SIZE}",
    )
    parser.add_argument(
        "--input-path",
        default=None,
        help="Caminho do CSV de entrada. Se omitido, usa CREATE_SAMPLE_INPUT_PATH ou data/urls_raw.csv.",
    )
    parser.add_argument(
        "--output-path",
        default=None,
        help="Caminho do CSV de saída. Se omitido, usa CREATE_SAMPLE_OUTPUT_PATH ou data/urls_raw_<size>.csv.",
    )
    parser.add_argument(
        "--dotenv",
        default=".env",
        help="Arquivo .env para carregar variáveis de ambiente. Use vazio para ignorar.",
    )
    return parser.parse_args()


def resolve_config(args):
    dotenv_path = (args.dotenv or "").strip()
    if dotenv_path:
        if not os.path.isabs(dotenv_path):
            dotenv_path = os.path.join(BASE_DIR, dotenv_path)
        load_dotenv_file(dotenv_path)

    sample_size = args.sample_size
    if sample_size is None:
        sample_size = env_or_default("CREATE_SAMPLE_SIZE", DEFAULT_SAMPLE_SIZE, int)

    input_path = args.input_path or os.getenv("CREATE_SAMPLE_INPUT_PATH")
    if input_path:
        if not os.path.isabs(input_path):
            input_path = os.path.join(BASE_DIR, input_path)
    else:
        input_path = os.path.join(BASE_DIR, "data", DEFAULT_INPUT_FILENAME)

    output_path = args.output_path or os.getenv("CREATE_SAMPLE_OUTPUT_PATH")
    if output_path:
        if not os.path.isabs(output_path):
            output_path = os.path.join(BASE_DIR, output_path)
    else:
        output_path = os.path.join(BASE_DIR, "data", f"urls_raw_{sample_size}.csv")

    return {
        "sample_size": sample_size,
        "input_path": input_path,
        "output_path": output_path,
    }


def main():
    args = parse_args()
    config = resolve_config(args)

    sample_size = config["sample_size"]
    input_path = config["input_path"]
    output_path = config["output_path"]

    if not os.path.exists(input_path):
        raise FileNotFoundError(f"Arquivo não encontrado: {input_path}")

    df = pd.read_csv(input_path)
    df.columns = df.columns.str.strip()

    df = df.rename(columns={
        "URL": "url",
        "Label": "label"
    })

    if "url" not in df.columns or "label" not in df.columns:
        raise ValueError("O arquivo precisa ter as colunas: url,label")

    df = df.dropna(subset=["url", "label"])

    df["label"] = df["label"].replace({
        "good": 1,
        "bad": -1
    })

    df["label"] = pd.to_numeric(df["label"], errors="coerce")
    df = df.dropna(subset=["label"])
    df["label"] = df["label"].astype(int)

    if len(df) < sample_size:
        raise ValueError(
            f"O dataset tem {len(df)} linhas, menor que o sample pedido ({sample_size})."
        )

    # split estratificado: pega exatamente a parte desejada
    df_sample, _ = train_test_split(
        df,
        train_size=sample_size,
        stratify=df["label"],
        random_state=42
    )

    df_sample.to_csv(output_path, index=False, encoding="utf-8")

    print("Sample estratificado criado com sucesso.")
    print(f"Entrada: {input_path}")
    print(f"Saída:   {output_path}")
    print(f"Linhas:  {len(df_sample)}")

    print("\nDistribuição no dataset original:")
    print(df["label"].value_counts(normalize=True).sort_index())

    print("\nDistribuição no sample:")
    print(df_sample["label"].value_counts(normalize=True).sort_index())

    print("\nContagem no sample:")
    print(df_sample["label"].value_counts().sort_index())


if __name__ == "__main__":
    main()
