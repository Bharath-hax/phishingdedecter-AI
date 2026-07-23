from __future__ import annotations

from feature_extractor import PhishingRuleModel, URLFeatureExtractor


def classify_url(url: str) -> dict:
    features = URLFeatureExtractor.extract_features(url)
    model = PhishingRuleModel()
    label, score = model.predict(features)
    return {
        "url": features.url,
        "label": label,
        "score": score,
        "hostname": features.hostname,
        "has_ip_address": features.has_ip_address,
        "has_shortener": features.has_shortener,
        "suspicious_keyword_hits": features.suspicious_keyword_hits,
        "suspicious_keyword_list": features.suspicious_keyword_list,
    }

