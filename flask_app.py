from __future__ import annotations

import json
import logging
import pickle
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

from flask import Flask, jsonify, render_template, request

from feature_extractor import FEATURE_COLUMNS, MODEL_VERSION, PhishingRuleModel, URLFeatureExtractor, predict_url_with_model


app = Flask(__name__)
MODEL_PATH = Path(__file__).with_name("phishing_model.pkl")
LOG_PATH = Path(__file__).with_name("prediction_log.jsonl")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")


def load_model():
    if MODEL_PATH.exists():
        try:
            with MODEL_PATH.open("rb") as handle:
                artifact = pickle.load(handle)

            if isinstance(artifact, dict) and "model" in artifact:
                feature_columns = artifact.get("feature_columns") or []
                if feature_columns != FEATURE_COLUMNS:
                    raise ValueError("Model feature schema mismatch")
                return artifact

            if hasattr(artifact, "predict"):
                return artifact
        except Exception:
            try:
                from modle_trainer import train_model, save_model
                trained_model = train_model()
                save_model(trained_model, MODEL_PATH)
                with MODEL_PATH.open("rb") as handle:
                    artifact = pickle.load(handle)
                return artifact
            except Exception:
                return PhishingRuleModel()
    else:
        try:
            from modle_trainer import train_model, save_model
            trained_model = train_model()
            save_model(trained_model, MODEL_PATH)
            with MODEL_PATH.open("rb") as handle:
                artifact = pickle.load(handle)
            return artifact
        except Exception:
            return PhishingRuleModel()

    return PhishingRuleModel()


def log_prediction(url: str, label: str, score: float) -> None:
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "model_version": MODEL_VERSION,
        "url": url,
        "label": label,
        "score": score,
    }
    with LOG_PATH.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record) + "\n")
    logging.info("Prediction: %s | %s | %.2f", url, label, score)


@app.get("/")
def home() -> str:
    return render_template("index.html")


@app.post("/predict")
def predict() -> Any:
    payload = request.get_json(silent=True) or {}
    url = payload.get("url") or payload.get("website") or ""

    if not isinstance(url, str) or not url.strip():
        return jsonify({"error": "A non-empty 'url' field is required."}), 400

    try:
        model = load_model()
        label, score = predict_url_with_model(model, url)
        features = URLFeatureExtractor.extract_features(url)
        log_prediction(features.url, label, score)
        model_version = MODEL_VERSION
        if isinstance(model, dict) and "version" in model:
            model_version = model["version"]
        return jsonify(
            {
                "url": features.url,
                "label": label,
                "score": score,
                "model_version": model_version,
                "features": {
                    "hostname": features.hostname,
                    "tld": features.tld,
                    "path_length": features.path_length,
                    "query_length": features.query_length,
                    "subdomain_count": features.subdomain_count,
                    "digit_ratio": round(features.digit_ratio, 4),
                    "special_char_ratio": round(features.special_char_ratio, 4),
                    "contains_at": features.contains_at,
                    "has_ip_address": features.has_ip_address,
                    "has_shortener": features.has_shortener,
                    "suspicious_keyword_hits": features.suspicious_keyword_hits,
                    "suspicious_keyword_list": features.suspicious_keyword_list,
                },
            }
        )
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception as exc:
        return jsonify({"error": f"Prediction failed: {exc}"}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)

