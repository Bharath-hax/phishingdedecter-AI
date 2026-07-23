from __future__ import annotations

import argparse
import pickle
from pathlib import Path

from feature_extractor import FEATURE_COLUMNS, PhishingRuleModel, URLFeatureExtractor, predict_url_with_model


MODEL_PATH = Path(__file__).with_name("phishing_model.pkl")


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
            return artifact
        except Exception:
            try:
                from modle_trainer import train_model, save_model
                model = train_model()
                save_model(model, MODEL_PATH)
                with MODEL_PATH.open("rb") as handle:
                    artifact = pickle.load(handle)
                return artifact
            except Exception:
                return PhishingRuleModel()
    return PhishingRuleModel()


def main() -> int:
    parser = argparse.ArgumentParser(description="Detect phishing URLs with a feature-driven ML pipeline.")
    parser.add_argument("url", nargs="?", help="The URL to classify.")
    args = parser.parse_args()

    url = args.url or ""
    if not url:
        parser.print_help()
        return 1

    model = load_model()
    label, score = predict_url_with_model(model, url)
    features = URLFeatureExtractor.extract_features(url)
    print(f"label={label}")
    print(f"score={score}")
    print(f"features={URLFeatureExtractor.to_feature_dict(features)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

