import pandas as pd
import random
# Legitimate domains
legit_domains = [
    "google.com", "youtube.com", "amazon.in", "facebook.com",
    "twitter.com", "instagram.com", "linkedin.com", "github.com",
    "wikipedia.org", "microsoft.com", "apple.com", "netflix.com",
    "stackoverflow.com", "reddit.com", "quora.com"
]
# Phishing keywords
phishing_words = [
    "login", "secure", "verify", "account", "update",
    "bank", "paypal", "free", "win", "bonus"
]
data = []
# Generate Legit URLs (500)
for _ in range(500):
    domain = random.choice(legit_domains)
    url = f"https://www.{domain}"
    data.append([url, 0])
# Generate Phishing URLs (500)
for _ in range(500):
    word1 = random.choice(phishing_words)
    word2 = random.choice(phishing_words)
    url = f"http://{word1}-{word2}-secure.com"
    data.append([url, 1])
# Create DataFrame
df = pd.DataFrame(data, columns=["url", "label"])
# Shuffle dataset
df = df.sample(frac=1).reset_index(drop=True)
# Save file
df.to_csv("data/raw_urls.csv", index=False)
print("Dataset generated with 1000 URLs!")
