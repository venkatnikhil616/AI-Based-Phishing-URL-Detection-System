import unittest
from features.feature_extraction import extract_features


class TestFeatureExtraction(unittest.TestCase):

    def test_legitimate_url(self):
        url = "https://www.google.com"
        features = extract_features(url)

        self.assertEqual(features[2], 1)  # has_https
        self.assertEqual(features[3], 0)  # has_at
        self.assertEqual(features[4], 0)  # has_hyphen

    def test_phishing_keywords(self):
        url = "http://secure-login-bank.com"
        features = extract_features(url)

        self.assertEqual(features[2], 0)  # not https
        self.assertEqual(features[4], 1)  # has hyphen
        self.assertEqual(features[6], 1)  # suspicious words

    def test_ip_address_url(self):
        url = "http://192.168.0.1/login"
        features = extract_features(url)

        self.assertEqual(features[5], 1)  # has IP
        self.assertEqual(features[6], 1)  # suspicious words

    def test_at_symbol(self):
        url = "http://login@secure-bank.com"
        features = extract_features(url)

        self.assertEqual(features[3], 1)  # has @
        self.assertEqual(features[6], 1)  # suspicious words


if __name__ == "__main__":
    unittest.main()
