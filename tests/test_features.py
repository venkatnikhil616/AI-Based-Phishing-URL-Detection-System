import unittest

from features.feature_extraction import extract_features


class TestFeatureExtraction(unittest.TestCase):

    def test_feature_count(self):
        """
        Ensure the feature extractor always returns
        exactly seven features in the expected format.
        """

        url = "https://www.google.com"

        features = extract_features(url)

        self.assertEqual(
            len(features),
            7
        )

        self.assertTrue(
            all(
                isinstance(feature, (int, float))
                for feature in features
            )
        )

    def test_legitimate_url(self):
        url = "https://www.google.com"

        features = extract_features(url)

        self.assertEqual(
            features[2],
            1
        )  # has_https

        self.assertEqual(
            features[3],
            0
        )  # has_at

        self.assertEqual(
            features[4],
            0
        )  # has_hyphen

    def test_phishing_keywords(self):
        url = "http://secure-login-bank.com"

        features = extract_features(url)

        self.assertEqual(
            features[2],
            0
        )  # not https

        self.assertEqual(
            features[4],
            1
        )  # has_hyphen

        self.assertEqual(
            features[6],
            1
        )  # suspicious words

    def test_ip_address_url(self):
        url = "http://192.168.0.1/login"

        features = extract_features(url)

        self.assertEqual(
            features[5],
            1
        )  # has_ip_address

        self.assertEqual(
            features[6],
            1
        )  # suspicious words

    def test_at_symbol(self):
        url = "http://login@secure-bank.com"

        features = extract_features(url)

        self.assertEqual(
            features[3],
            1
        )  # has_at

        self.assertEqual(
            features[6],
            1
        )  # suspicious words

    def test_http_url_without_scheme(self):
        """
        Ensure URLs without an explicit scheme are
        handled correctly by the feature extractor.
        """

        url = "example.com"

        features = extract_features(url)

        self.assertEqual(
            len(features),
            7
        )

    def test_empty_url(self):
        """
        Empty input should raise ValueError.
        """

        with self.assertRaises(ValueError):
            extract_features("")

    def test_non_string_url(self):
        """
        Non-string input should raise TypeError.
        """

        with self.assertRaises(TypeError):
            extract_features(None)


if __name__ == "__main__":
    unittest.main()
