from __future__ import annotations

import ipaddress
import pickle
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Tuple
from urllib.parse import parse_qs, urlparse


SUSPICIOUS_KEYWORDS = {
    "login", "signin", "verify", "secure", "confirm", "update", "bank",
    "account", "password", "credential", "payment", "invoice", "unlock",
    "suspended", "amazon", "paypal", "apple", "office", "microsoft",
    "dropbox", "netflix", "google", "icloud", "recovery", "alert",
    "americanexpress", "amex", "capitalone", "chase", "citibank",
    "wellsfargo", "bankofamerica", "wellsfargo", "paypal", "steam"
}

BRAND_IMPERSONATION_KEYWORDS = {
    "americanexpress", "amex", "bankofamerica", "capitalone", "chase",
    "citibank", "wellsfargo", "paypal", "apple", "microsoft", "office",
    "amazon", "netflix", "dropbox", "google", "github", "linkedin"
}

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "shorturl.at"
}

SUSPICIOUS_TLDS = {"tk", "ml", "ga", "cf", "xyz", "top", "club", "bid", "loan", "review"}

DOMAIN_PATTERN = re.compile(r"(?:[a-z0-9-]+\.)+[a-z]{2,}", re.IGNORECASE)

FEATURE_COLUMNS = [
    "url_length", "hostname_length", "path_length", "query_length", "fragment_length",
    "subdomain_count", "path_segment_count", "digit_ratio", "special_char_ratio",
    "hyphen_count", "underscore_count", "percent_encoded_count", "contains_at",
    "has_ip_address", "has_shortener", "suspicious_keyword_hits", "has_query",
    "has_fragment", "has_port", "is_secure_scheme", "param_count", "is_suspicious_tld",
    "path_domain_count", "brand_impersonation_hits", "has_hidden_brand_domain"
]
MODEL_VERSION = "1.1.0"


@dataclass
class URLFeatures:
    url: str
    hostname: str
    tld: str
    url_length: int
    hostname_length: int
    path_length: int
    query_length: int
    fragment_length: int
    subdomain_count: int
    path_segment_count: int
    digit_ratio: float
    special_char_ratio: float
    hyphen_count: int
    underscore_count: int
    percent_encoded_count: int
    contains_at: bool
    has_ip_address: bool
    has_shortener: bool
    suspicious_keyword_hits: int
    suspicious_keyword_list: List[str]
    has_query: bool
    has_fragment: bool
    has_port: bool
    is_secure_scheme: bool
    param_count: int
    is_suspicious_tld: bool
    path_domain_count: int
    brand_impersonation_hits: int
    has_hidden_brand_domain: bool


class URLFeatureExtractor:
    """Extract a broad, industrial-strength feature set from any URL."""

    @staticmethod
    def normalize_url(raw_url: str) -> str:
        if not isinstance(raw_url, str):
            raise ValueError("URL must be a string value.")

        candidate = raw_url.strip()
        if not candidate:
            raise ValueError("URL is empty.")

        if candidate.startswith(("http://", "https://")):
            normalized = candidate
        else:
            normalized = f"https://{candidate}"

        parsed = urlparse(normalized)
        if not parsed.scheme:
            normalized = f"https://{candidate}"
            parsed = urlparse(normalized)

        if not parsed.netloc:
            raise ValueError("URL does not contain a valid host.")

        return normalized

    @staticmethod
    def _safe_hostname(parsed) -> str:
        hostname = parsed.hostname or ""
        return hostname.lower().strip()

    @staticmethod
    def extract_features(url: str) -> URLFeatures:
        normalized = URLFeatureExtractor.normalize_url(url)
        parsed = urlparse(normalized)
        hostname = URLFeatureExtractor._safe_hostname(parsed)
        if not hostname:
            raise ValueError("URL could not be normalized to a hostname.")

        path = parsed.path or ""
        query = parsed.query or ""
        fragment = parsed.fragment or ""
        params = parse_qs(query)
        path_segments = [segment for segment in path.split("/") if segment]
        path_text = f"{path} {query} {fragment}".lower()
        count_dots = hostname.count(".")
        subdomain_count = max(count_dots - 1, 0)
        tld = hostname.split(".")[-1] if "." in hostname else ""

        path_domain_count = 0
        brand_impersonation_hits = 0
        brand_impersonation_domains: List[str] = []
        for match in DOMAIN_PATTERN.finditer(path_text):
            candidate = match.group(0).strip(".")
            if candidate and candidate.count(".") >= 1:
                path_domain_count += 1
                if any(keyword in candidate for keyword in BRAND_IMPERSONATION_KEYWORDS):
                    brand_impersonation_hits += 1
                    if candidate not in brand_impersonation_domains:
                        brand_impersonation_domains.append(candidate)

        has_hidden_brand_domain = brand_impersonation_hits > 0 and hostname not in brand_impersonation_domains

        digits = sum(ch.isdigit() for ch in hostname)
        digit_ratio = digits / max(len(hostname), 1)
        special_char_ratio = sum(not (ch.isalnum() or ch in "-.") for ch in hostname) / max(len(hostname), 1)
        hyphen_count = hostname.count("-")
        underscore_count = hostname.count("_")
        percent_encoded_count = normalized.count("%")
        contains_at = "@" in normalized
        has_ip_address = False
        try:
            ipaddress.ip_address(hostname)
            has_ip_address = True
        except ValueError:
            pass

        suspicious_keyword_hits = 0
        suspicious_keyword_list: List[str] = []
        lowered_host = hostname.lower()
        lowered_path = f"{path} {query} {fragment}".lower()
        for keyword in SUSPICIOUS_KEYWORDS:
            if keyword in lowered_host or keyword in lowered_path:
                suspicious_keyword_hits += 1
                if keyword not in suspicious_keyword_list:
                    suspicious_keyword_list.append(keyword)

        has_shortener = hostname in SHORTENER_DOMAINS or any(hostname.endswith(f".{item}") for item in SHORTENER_DOMAINS)
        has_query = bool(query)
        has_fragment = bool(fragment)
        has_port = parsed.port is not None
        is_secure_scheme = parsed.scheme.lower() == "https"
        param_count = len(params)
        is_suspicious_tld = tld in SUSPICIOUS_TLDS

        return URLFeatures(
            url=normalized,
            hostname=hostname,
            tld=tld,
            url_length=len(normalized),
            hostname_length=len(hostname),
            path_length=len(path),
            query_length=len(query),
            fragment_length=len(fragment),
            subdomain_count=subdomain_count,
            path_segment_count=len(path_segments),
            digit_ratio=digit_ratio,
            special_char_ratio=special_char_ratio,
            hyphen_count=hyphen_count,
            underscore_count=underscore_count,
            percent_encoded_count=percent_encoded_count,
            contains_at=contains_at,
            has_ip_address=has_ip_address,
            has_shortener=has_shortener,
            suspicious_keyword_hits=suspicious_keyword_hits,
            suspicious_keyword_list=suspicious_keyword_list,
            has_query=has_query,
            has_fragment=has_fragment,
            has_port=has_port,
            is_secure_scheme=is_secure_scheme,
            param_count=param_count,
            is_suspicious_tld=is_suspicious_tld,
            path_domain_count=path_domain_count,
            brand_impersonation_hits=brand_impersonation_hits,
            has_hidden_brand_domain=has_hidden_brand_domain,
        )

    @staticmethod
    def to_feature_dict(features: URLFeatures) -> Dict[str, Any]:
        return {
            "url_length": features.url_length,
            "hostname_length": features.hostname_length,
            "path_length": features.path_length,
            "query_length": features.query_length,
            "fragment_length": features.fragment_length,
            "subdomain_count": features.subdomain_count,
            "path_segment_count": features.path_segment_count,
            "digit_ratio": features.digit_ratio,
            "special_char_ratio": features.special_char_ratio,
            "hyphen_count": features.hyphen_count,
            "underscore_count": features.underscore_count,
            "percent_encoded_count": features.percent_encoded_count,
            "contains_at": int(features.contains_at),
            "has_ip_address": int(features.has_ip_address),
            "has_shortener": int(features.has_shortener),
            "suspicious_keyword_hits": features.suspicious_keyword_hits,
            "has_query": int(features.has_query),
            "has_fragment": int(features.has_fragment),
            "has_port": int(features.has_port),
            "is_secure_scheme": int(features.is_secure_scheme),
            "param_count": features.param_count,
            "is_suspicious_tld": int(features.is_suspicious_tld),
            "path_domain_count": features.path_domain_count,
            "brand_impersonation_hits": features.brand_impersonation_hits,
            "has_hidden_brand_domain": int(features.has_hidden_brand_domain),
        }

    @staticmethod
    def to_feature_vector(features: URLFeatures) -> List[float]:
        return [
            features.url_length,
            features.hostname_length,
            features.path_length,
            features.query_length,
            features.fragment_length,
            features.subdomain_count,
            features.path_segment_count,
            features.digit_ratio,
            features.special_char_ratio,
            features.hyphen_count,
            features.underscore_count,
            features.percent_encoded_count,
            int(features.contains_at),
            int(features.has_ip_address),
            int(features.has_shortener),
            features.suspicious_keyword_hits,
            int(features.has_query),
            int(features.has_fragment),
            int(features.has_port),
            int(features.is_secure_scheme),
            features.param_count,
            int(features.is_suspicious_tld),
            features.path_domain_count,
            features.brand_impersonation_hits,
            int(features.has_hidden_brand_domain),
        ]


class PhishingRuleModel:
    """A lightweight, dependency-free fallback rule model for production-friendly phishing detection."""

    def __init__(self, threshold: float = 55.0) -> None:
        self.threshold = threshold

    def score(self, features: URLFeatures) -> float:
        score = 0.0

        if features.has_ip_address:
            score += 25
        if features.contains_at:
            score += 20
        if features.has_shortener:
            score += 32
        if features.subdomain_count >= 2:
            score += 18
        if features.subdomain_count >= 4:
            score += 12
        if features.path_length > 24:
            score += 12
        if features.query_length > 12:
            score += 10
        if features.fragment_length > 5:
            score += 6
        if features.digit_ratio > 0.15:
            score += 10
        if features.special_char_ratio > 0.10:
            score += 8
        if features.hyphen_count >= 2:
            score += 8
        if features.underscore_count >= 1:
            score += 6
        if features.percent_encoded_count >= 1:
            score += 6
        if features.hostname_length > 20:
            score += 10
        if features.hostname.startswith(("mail.", "webmail.", "login.", "secure.", "signin.")):
            score += 12
        if features.suspicious_keyword_hits:
            score += min(42, features.suspicious_keyword_hits * 14)
        if features.path_domain_count >= 1:
            score += 16
        if features.brand_impersonation_hits:
            score += min(48, features.brand_impersonation_hits * 18)
        if features.has_hidden_brand_domain:
            score += 24
        if features.has_port:
            score += 8
        if features.param_count >= 3:
            score += 8
        if features.is_suspicious_tld:
            score += 14
        if not features.tld or len(features.tld) < 2:
            score += 12
        if not features.is_secure_scheme:
            score += 10

        return round(score, 2)

    def predict(self, features: URLFeatures) -> Tuple[str, float]:
        score = self.score(features)
        label = "phishing" if score >= self.threshold else "safe"
        return label, score

    def predict_url(self, url: str) -> Tuple[str, float]:
        features = URLFeatureExtractor.extract_features(url)
        return self.predict(features)

    def save(self, path: str | Path) -> None:
        with Path(path).open("wb") as model_file:
            pickle.dump(self, model_file)

    @classmethod
    def load(cls, path: str | Path) -> "PhishingRuleModel":
        with Path(path).open("rb") as model_file:
            return pickle.load(model_file)


def predict_url_with_model(model: Any, url: str) -> Tuple[str, float]:
    features = URLFeatureExtractor.extract_features(url)
    rule_model = PhishingRuleModel()
    rule_label, rule_score = rule_model.predict(features)

    active_model = model
    if isinstance(model, dict) and "model" in model:
        active_model = model["model"]

    if hasattr(active_model, "predict") and not isinstance(active_model, PhishingRuleModel):
        import pandas as pd
        feature_dict = URLFeatureExtractor.to_feature_dict(features)
        frame = pd.DataFrame([feature_dict], columns=FEATURE_COLUMNS)
        if hasattr(active_model, "feature_names_in_"):
            frame = frame.reindex(columns=list(active_model.feature_names_in_), fill_value=0)
        prediction = int(active_model.predict(frame)[0])
        probability = 0.0
        if hasattr(active_model, "predict_proba"):
            probability = max(active_model.predict_proba(frame)[0])
        ml_label = "phishing" if prediction == 1 else "safe"
        ml_score = round(float(probability) * 100, 2)

        combined_score = max(rule_score, ml_score)
        if rule_label == "phishing" or ml_label == "phishing":
            if any([
                features.has_hidden_brand_domain,
                features.brand_impersonation_hits > 0,
                features.path_domain_count >= 1,
                rule_score >= 60.0,
                ml_score >= 60.0,
            ]):
                return "phishing", round(combined_score, 2)

        return ml_label, round(ml_score, 2)

    return rule_label, rule_score

