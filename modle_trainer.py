from __future__ import annotations

import pickle
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split

from feature_extractor import FEATURE_COLUMNS, MODEL_VERSION, URLFeatureExtractor


def load_dataset_from_csv(path: str | Path) -> pd.DataFrame:
    dataset = pd.read_csv(path)
    rows = []
    for _, row in dataset.iterrows():
        features = URLFeatureExtractor.extract_features(row["url"])
        rows.append({**URLFeatureExtractor.to_feature_dict(features), "label": int(row["label"])})

    frame = pd.DataFrame(rows)
    frame = frame.reindex(columns=FEATURE_COLUMNS + ["label"], fill_value=0)
    return frame


def build_training_data() -> pd.DataFrame:
    csv_path = Path(__file__).with_name("phishing_urls.csv")
    if csv_path.exists():
        return load_dataset_from_csv(csv_path)

    rows = []
    safe_urls = [
        "https://www.google.com/search?q=python",
        "https://www.youtube.com/watch?v=abc",
        "https://example.com/index.html",
        "https://github.com/microsoft",
        "https://www.stackoverflow.com/questions",
        "https://www.linkedin.com/company/tech",
        "https://www.amazon.in/",
        "https://www.wikipedia.org/",
        "https://www.nasa.gov/",
        "https://www.microsoft.com/en-us/",
        "https://www.americanexpress.com/",
        "https://www.apple.com/",
        "https://www.linkedin.com/",
    ]
    suspicious_urls = [
        "https://login.paypal-secure-update.account.example.com/confirm",
        "http://192.168.1.15/login",
        "https://secure-verify-bank-account-update.com/confirm",
        "https://bit.ly/xyz123",
        "https://signin.office365-security-account.com/password",
        "https://dropbox-account-recovery.net/confirm",
        "https://account-verify-login-update.net/reset",
        "https://icloud-secure-recovery-verify.tk/confirm",
        "https://payment-secure-review-now.com/confirm",
        "https://mail.printakid.com/www.online.americanexpress.com/index.html",
        "https://login.secure.paypal.com/https://www.paypal.com/confirm",
        "https://secure.bankofamerica-update.net/index.php?redirect=www.bankofamerica.com",
        "https://www.paypal.com.update-account-check.com/signin",
        "https://verify-apple-id-secure-login.net/account",
        "https://login.microsoft-office-update.com/confirm",
        "https://citibank-security-recovery.online/account/verify",
    ]

    for url in safe_urls:
        features = URLFeatureExtractor.extract_features(url)
        rows.append({**URLFeatureExtractor.to_feature_dict(features), "label": 0})

    for url in suspicious_urls:
        features = URLFeatureExtractor.extract_features(url)
        rows.append({**URLFeatureExtractor.to_feature_dict(features), "label": 1})

    frame = pd.DataFrame(rows)
    frame = frame.reindex(columns=FEATURE_COLUMNS + ["label"], fill_value=0)
    return frame


def train_model() -> RandomForestClassifier:
    data = build_training_data()
    X = data[FEATURE_COLUMNS]
    y = data["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    model = RandomForestClassifier(
        n_estimators=140,
        max_depth=6,
        min_samples_split=2,
        random_state=42,
        class_weight="balanced"
    )
    model.fit(X_train, y_train)

    accuracy = model.score(X_test, y_test)
    print(f"Training accuracy: {accuracy:.4f}")
    return model


def save_model(model: RandomForestClassifier, path: str | Path) -> None:
    artifact = {
        "model": model,
        "version": MODEL_VERSION,
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "feature_columns": FEATURE_COLUMNS,
    }
    with Path(path).open("wb") as handle:
        pickle.dump(artifact, handle)


if __name__ == "__main__":
    model = train_model()
    save_model(model, Path(__file__).with_name("phishing_model.pkl"))
    print("Advanced phishing model saved to phishing_model.pkl")

