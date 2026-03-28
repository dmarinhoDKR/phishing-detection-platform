import json
import os

from src.detector_phishing_v2 import check_url_detailed
from src.email_analysis import analyze_email


BASE_DIR = os.path.abspath(os.path.dirname(__file__))
CALIBRATION_DIR = os.path.join(BASE_DIR, "data", "calibration_cases")
OUTPUT_PATH = os.path.join(BASE_DIR, "model", "calibration_results.json")


def load_cases(filename: str):
    path = os.path.join(CALIBRATION_DIR, filename)
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def evaluate_url_cases():
    cases = load_cases("url_cases.json")
    results = []

    for case in cases:
        result = check_url_detailed(case["url"])
        results.append(
            {
                "case_id": case["case_id"],
                "type": "url",
                "expected_band": case["expected_band"],
                "predicted_band": result["faixa_risco"],
                "match": result["faixa_risco"] == case["expected_band"],
                "score": result["prob_phishing"],
                "notes": case.get("notes", ""),
            }
        )

    return results


def evaluate_email_cases():
    cases = load_cases("email_cases.json")
    results = []

    for case in cases:
        result = analyze_email(
            display_name=case.get("display_name", ""),
            sender_email=case.get("sender_email", ""),
            subject=case.get("subject", ""),
            body_excerpt=case.get("body_excerpt", ""),
            button_url=case.get("button_url", ""),
            raw_headers=case.get("raw_headers", ""),
            attachments_blocked=case.get("attachments_blocked", False),
            marked_as_junk=case.get("marked_as_junk", False),
        )
        results.append(
            {
                "case_id": case["case_id"],
                "type": "email",
                "expected_band": case["expected_band"],
                "predicted_band": result["faixa_risco"],
                "match": result["faixa_risco"] == case["expected_band"],
                "score": result["score_email"],
                "notes": case.get("notes", ""),
            }
        )

    return results


def summarize(results):
    total = len(results)
    matches = sum(1 for item in results if item["match"])
    mismatches = [item for item in results if not item["match"]]
    return {
        "total_cases": total,
        "matches": matches,
        "accuracy_against_expected_band": round(matches / total, 6) if total else 0.0,
        "mismatches": mismatches,
    }


def save_results(payload):
    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    with open(OUTPUT_PATH, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2)


def main():
    payload = build_payload()
    save_results(payload)

    print("Resumo da calibração:")
    print(json.dumps(payload["summary"], ensure_ascii=False, indent=2))
    print(f"\nResultados salvos em: {OUTPUT_PATH}")


def build_payload():
    url_results = evaluate_url_cases()
    email_results = evaluate_email_cases()
    all_results = url_results + email_results

    return {
        "summary": summarize(all_results),
        "url_cases": url_results,
        "email_cases": email_results,
    }


if __name__ == "__main__":
    main()
