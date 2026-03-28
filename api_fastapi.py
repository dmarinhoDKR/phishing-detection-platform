import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from run_calibration_cases import build_payload
from src.detector_phishing_v2 import check_url_detailed
from src.email_analysis import analyze_email


BASE_DIR = os.path.abspath(os.path.dirname(__file__))

app = FastAPI(
    title="Phishing AI API",
    version="1.0.0",
    description="API do baseline oficial para análise de URLs e emails suspeitos.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class UrlAnalysisRequest(BaseModel):
    url: str = Field(..., description="URL para análise.")


class EmailAnalysisRequest(BaseModel):
    display_name: str = ""
    sender_email: str = ""
    subject: str = ""
    body_excerpt: str = ""
    button_url: str = ""
    raw_headers: str = ""
    attachments_blocked: bool = False
    marked_as_junk: bool = False


@app.get("/health")
def health():
    return {
        "status": "ok",
        "baseline": {
            "features": 16,
            "threshold": 0.50,
            "dataset": "urls_raw.csv (dataset antigo restaurado)",
        },
    }


@app.get("/mobile/bootstrap")
def mobile_bootstrap():
    return {
        "app_name": "Phishing AI Mobile",
        "recommended_url_placeholder": "https://exemplo.com",
        "recommended_email_fields": [
            "display_name",
            "sender_email",
            "subject",
            "body_excerpt",
            "button_url",
            "raw_headers",
            "attachments_blocked",
            "marked_as_junk",
        ],
        "risk_bands": {
            "legitimo": "prob_phishing < 0.40",
            "suspeito": "0.40 <= prob_phishing < 0.60",
            "phishing": "prob_phishing >= 0.60",
        },
    }


@app.get("/")
def root():
    return {
        "name": "Phishing AI API",
        "docs": "/docs",
        "health": "/health",
        "endpoints": [
            "/analyze/url",
            "/analyze/email",
            "/calibration",
        ],
    }


@app.post("/analyze/url")
def analyze_url(payload: UrlAnalysisRequest):
    result = check_url_detailed(payload.url)
    return {
        "input": payload.model_dump(),
        "result": result,
    }


@app.post("/analyze/email")
def analyze_email_endpoint(payload: EmailAnalysisRequest):
    result = analyze_email(**payload.model_dump())
    return {
        "input": payload.model_dump(),
        "result": result,
    }


@app.get("/calibration")
def calibration():
    return build_payload()


def main():
    import uvicorn

    uvicorn.run(
        "api_fastapi:app",
        host="0.0.0.0",
        port=8000,
        reload=False,
    )


if __name__ == "__main__":
    main()
