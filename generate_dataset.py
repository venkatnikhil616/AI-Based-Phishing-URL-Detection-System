import os
import random

import pandas as pd


# --------------------------------------------------
# PROJECT PATHS
# --------------------------------------------------

BASE_DIR = os.path.abspath(
    os.path.dirname(__file__)
)

DATA_DIR = os.path.join(
    BASE_DIR,
    "data"
)

OUTPUT_PATH = os.path.join(
    DATA_DIR,
    "raw_urls.csv"
)


# --------------------------------------------------
# LEGITIMATE DOMAINS
# --------------------------------------------------

legit_domains = [
    "google.com",
    "youtube.com",
    "amazon.in",
    "facebook.com",
    "twitter.com",
    "instagram.com",
    "linkedin.com",
    "github.com",
    "wikipedia.org",
    "microsoft.com",
    "apple.com",
    "netflix.com",
    "stackoverflow.com",
    "reddit.com",
    "quora.com",
]


# --------------------------------------------------
# PHISHING KEYWORDS
# --------------------------------------------------

phishing_words = [
    "login",
    "secure",
    "verify",
    "account",
    "update",
    "bank",
    "paypal",
    "free",
    "win",
    "bonus",
]


# --------------------------------------------------
# DATASET GENERATION
# --------------------------------------------------

def generate_dataset():
    data = []

    # --------------------------------------------------
    # GENERATE LEGITIMATE URLs
    # --------------------------------------------------

    for _ in range(500):
        domain = random.choice(
            legit_domains
        )

        url = f"https://www.{domain}"

        data.append(
            [url, 0]
        )

    # --------------------------------------------------
    # GENERATE PHISHING URLs
    # --------------------------------------------------

    for _ in range(500):
        word1 = random.choice(
            phishing_words
        )

        word2 = random.choice(
            phishing_words
        )

        url = (
            f"http://{word1}-"
            f"{word2}-secure.com"
        )

        data.append(
            [url, 1]
        )

    # --------------------------------------------------
    # CREATE DATAFRAME
    # --------------------------------------------------

    df = pd.DataFrame(
        data,
        columns=[
            "url",
            "label"
        ]
    )

    # --------------------------------------------------
    # SHUFFLE DATASET
    # --------------------------------------------------

    df = df.sample(
        frac=1,
        random_state=42
    ).reset_index(
        drop=True
    )

    # --------------------------------------------------
    # CREATE DATA DIRECTORY
    # --------------------------------------------------

    os.makedirs(
        DATA_DIR,
        exist_ok=True
    )

    # --------------------------------------------------
    # SAVE DATASET
    # --------------------------------------------------

    df.to_csv(
        OUTPUT_PATH,
        index=False
    )

    print(
        f"Dataset generated successfully: {OUTPUT_PATH}"
    )

    print(
        f"Total URLs: {len(df)}"
    )

    print(
        f"Legitimate URLs: {(df['label'] == 0).sum()}"
    )

    print(
        f"Phishing URLs: {(df['label'] == 1).sum()}"
    )


# --------------------------------------------------
# SCRIPT ENTRY POINT
# --------------------------------------------------

if __name__ == "__main__":
    generate_dataset()
