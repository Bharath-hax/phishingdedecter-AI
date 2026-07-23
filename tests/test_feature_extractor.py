import unittest

from feature_extractor import PhishingRuleModel, URLFeatureExtractor


class FeatureExtractorRegressionTests(unittest.TestCase):
    def test_hidden_brand_domain_in_path_is_flagged_as_phishing(self):
        url = "mail.printakid.com/www.online.americanexpress.com/index.html"
        features = URLFeatureExtractor.extract_features(url)
        label, score = PhishingRuleModel().predict(features)
        self.assertEqual(label, "phishing")
        self.assertGreaterEqual(score, 55.0)


if __name__ == "__main__":
    unittest.main()
