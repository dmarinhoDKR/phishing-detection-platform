import json
import os

import numpy as np
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)


def predict_with_threshold(prob_phishing, threshold):
    return np.where(prob_phishing >= threshold, -1, 1)


def _as_binary_phishing(y_true):
    arr = np.asarray(y_true)
    return np.where(arr == -1, 1, 0)


def calculate_metrics(y_true, y_pred, prob_phishing):
    y_true_bin = _as_binary_phishing(y_true)

    metrics = {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "balanced_accuracy": float(balanced_accuracy_score(y_true, y_pred)),
        "precision_phishing": float(precision_score(y_true, y_pred, pos_label=-1, zero_division=0)),
        "recall_phishing": float(recall_score(y_true, y_pred, pos_label=-1, zero_division=0)),
        "f1_phishing": float(f1_score(y_true, y_pred, pos_label=-1, zero_division=0)),
        "precision_legit": float(precision_score(y_true, y_pred, pos_label=1, zero_division=0)),
        "recall_legit": float(recall_score(y_true, y_pred, pos_label=1, zero_division=0)),
        "f1_legit": float(f1_score(y_true, y_pred, pos_label=1, zero_division=0)),
        "roc_auc_phishing": float(roc_auc_score(y_true_bin, prob_phishing)),
        "confusion_matrix": confusion_matrix(y_true, y_pred, labels=[-1, 1]).tolist(),
        "classification_report": classification_report(
            y_true,
            y_pred,
            labels=[-1, 1],
            target_names=["phishing", "legit"],
            output_dict=True,
            zero_division=0,
        ),
    }
    return metrics


def find_best_threshold(y_true, prob_phishing, metric_name="f1_phishing"):
    best = None

    for threshold in np.arange(0.05, 0.96, 0.01):
        y_pred = predict_with_threshold(prob_phishing, threshold)
        metrics = calculate_metrics(y_true, y_pred, prob_phishing)
        score = metrics.get(metric_name)

        candidate = {
            "threshold": round(float(threshold), 2),
            "score": float(score),
            "metrics": metrics,
        }

        if best is None:
            best = candidate
            continue

        if candidate["score"] > best["score"]:
            best = candidate
            continue

        if candidate["score"] == best["score"]:
            if candidate["metrics"]["recall_phishing"] > best["metrics"]["recall_phishing"]:
                best = candidate
                continue
            if (
                candidate["metrics"]["recall_phishing"] == best["metrics"]["recall_phishing"]
                and candidate["metrics"]["precision_phishing"] > best["metrics"]["precision_phishing"]
            ):
                best = candidate

    return best


def cv_summary(scores):
    arr = np.asarray(scores, dtype=float)
    return {
        "scores": [float(x) for x in arr.tolist()],
        "mean": float(arr.mean()),
        "std": float(arr.std()),
        "min": float(arr.min()),
        "max": float(arr.max()),
    }


def save_metrics(metrics_path, payload):
    metrics_dir = os.path.dirname(metrics_path)
    if metrics_dir:
        os.makedirs(metrics_dir, exist_ok=True)
    with open(metrics_path, "w", encoding="utf-8") as file:
        json.dump(payload, file, ensure_ascii=False, indent=2)
