import json
import os

from run_calibration_cases import build_payload, load_cases
from src.detector_phishing_v2 import check_url_detailed
from src.email_analysis import analyze_email


BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CALIBRATION_DIR = os.path.join(BASE_DIR, "data", "calibration_cases")


def test_calibration_suite_matches_expected_bands():
    payload = build_payload()
    assert payload["summary"]["total_cases"] >= 1
    assert payload["summary"]["mismatches"] == []
    assert payload["summary"]["accuracy_against_expected_band"] == 1.0


def test_url_calibration_cases_individually_match():
    for case in load_cases("url_cases.json"):
        result = check_url_detailed(case["url"])
        assert result["faixa_risco"] == case["expected_band"], case["case_id"]


def test_email_calibration_cases_individually_match():
    for case in load_cases("email_cases.json"):
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
        assert result["faixa_risco"] == case["expected_band"], case["case_id"]


def test_calibration_files_have_expected_minimum_shape():
    url_cases_path = os.path.join(CALIBRATION_DIR, "url_cases.json")
    email_cases_path = os.path.join(CALIBRATION_DIR, "email_cases.json")

    with open(url_cases_path, "r", encoding="utf-8") as handle:
        url_cases = json.load(handle)
    with open(email_cases_path, "r", encoding="utf-8") as handle:
        email_cases = json.load(handle)

    assert all("case_id" in case and "expected_band" in case and "url" in case for case in url_cases)
    assert all("case_id" in case and "expected_band" in case and "sender_email" in case for case in email_cases)
